rule TTP_XOR_WriteProcessMemory_7248 {
  strings:
    $key_7248 = { 25 3a [2] 17 18 [2] 11 2d [2] 3f 2d [2] 00 31 }

  condition:
    any of them
}