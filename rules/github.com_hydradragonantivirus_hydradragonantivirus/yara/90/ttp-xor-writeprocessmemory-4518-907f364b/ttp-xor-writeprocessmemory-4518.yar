rule TTP_XOR_WriteProcessMemory_4518 {
  strings:
    $key_4518 = { 12 6a [2] 20 48 [2] 26 7d [2] 08 7d [2] 37 61 }

  condition:
    any of them
}