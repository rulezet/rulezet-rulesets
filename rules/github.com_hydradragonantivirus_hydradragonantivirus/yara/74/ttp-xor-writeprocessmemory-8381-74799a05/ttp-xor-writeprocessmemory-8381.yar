rule TTP_XOR_WriteProcessMemory_8381 {
  strings:
    $key_8381 = { d4 f3 [2] e6 d1 [2] e0 e4 [2] ce e4 [2] f1 f8 }

  condition:
    any of them
}