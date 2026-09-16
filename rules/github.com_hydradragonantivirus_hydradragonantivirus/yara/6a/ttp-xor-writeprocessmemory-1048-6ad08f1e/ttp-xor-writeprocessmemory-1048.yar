rule TTP_XOR_WriteProcessMemory_1048 {
  strings:
    $key_1048 = { 47 3a [2] 75 18 [2] 73 2d [2] 5d 2d [2] 62 31 }

  condition:
    any of them
}