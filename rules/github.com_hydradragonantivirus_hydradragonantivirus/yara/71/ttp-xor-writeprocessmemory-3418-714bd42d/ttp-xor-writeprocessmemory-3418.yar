rule TTP_XOR_WriteProcessMemory_3418 {
  strings:
    $key_3418 = { 63 6a [2] 51 48 [2] 57 7d [2] 79 7d [2] 46 61 }

  condition:
    any of them
}