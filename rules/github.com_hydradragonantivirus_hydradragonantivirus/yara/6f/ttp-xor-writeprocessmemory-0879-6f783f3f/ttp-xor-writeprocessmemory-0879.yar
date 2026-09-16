rule TTP_XOR_WriteProcessMemory_0879 {
  strings:
    $key_0879 = { 5f 0b [2] 6d 29 [2] 6b 1c [2] 45 1c [2] 7a 00 }

  condition:
    any of them
}