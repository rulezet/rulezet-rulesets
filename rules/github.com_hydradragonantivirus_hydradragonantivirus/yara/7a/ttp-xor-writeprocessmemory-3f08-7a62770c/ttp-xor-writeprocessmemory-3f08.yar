rule TTP_XOR_WriteProcessMemory_3f08 {
  strings:
    $key_3f08 = { 68 7a [2] 5a 58 [2] 5c 6d [2] 72 6d [2] 4d 71 }

  condition:
    any of them
}