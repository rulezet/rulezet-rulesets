rule TTP_XOR_WriteProcessMemory_5f08 {
  strings:
    $key_5f08 = { 08 7a [2] 3a 58 [2] 3c 6d [2] 12 6d [2] 2d 71 }

  condition:
    any of them
}