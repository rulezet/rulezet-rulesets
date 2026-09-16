rule TTP_XOR_WriteProcessMemory_1af9 {
  strings:
    $key_1af9 = { 4d 8b [2] 7f a9 [2] 79 9c [2] 57 9c [2] 68 80 }

  condition:
    any of them
}