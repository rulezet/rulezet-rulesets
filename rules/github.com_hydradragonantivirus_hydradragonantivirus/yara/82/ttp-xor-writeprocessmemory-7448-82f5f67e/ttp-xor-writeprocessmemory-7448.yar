rule TTP_XOR_WriteProcessMemory_7448 {
  strings:
    $key_7448 = { 23 3a [2] 11 18 [2] 17 2d [2] 39 2d [2] 06 31 }

  condition:
    any of them
}