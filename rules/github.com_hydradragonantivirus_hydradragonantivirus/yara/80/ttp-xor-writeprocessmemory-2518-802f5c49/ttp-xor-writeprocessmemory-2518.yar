rule TTP_XOR_WriteProcessMemory_2518 {
  strings:
    $key_2518 = { 72 6a [2] 40 48 [2] 46 7d [2] 68 7d [2] 57 61 }

  condition:
    any of them
}