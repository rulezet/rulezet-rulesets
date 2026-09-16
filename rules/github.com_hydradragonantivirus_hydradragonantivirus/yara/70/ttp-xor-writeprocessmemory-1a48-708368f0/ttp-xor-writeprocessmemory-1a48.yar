rule TTP_XOR_WriteProcessMemory_1a48 {
  strings:
    $key_1a48 = { 4d 3a [2] 7f 18 [2] 79 2d [2] 57 2d [2] 68 31 }

  condition:
    any of them
}