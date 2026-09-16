rule TTP_XOR_WriteProcessMemory_4879 {
  strings:
    $key_4879 = { 1f 0b [2] 2d 29 [2] 2b 1c [2] 05 1c [2] 3a 00 }

  condition:
    any of them
}