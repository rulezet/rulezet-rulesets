rule TTP_XOR_WriteProcessMemory_7148 {
  strings:
    $key_7148 = { 26 3a [2] 14 18 [2] 12 2d [2] 3c 2d [2] 03 31 }

  condition:
    any of them
}