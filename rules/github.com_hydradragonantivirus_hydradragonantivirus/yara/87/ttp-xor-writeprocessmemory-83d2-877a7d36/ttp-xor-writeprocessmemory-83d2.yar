rule TTP_XOR_WriteProcessMemory_83d2 {
  strings:
    $key_83d2 = { d4 a0 [2] e6 82 [2] e0 b7 [2] ce b7 [2] f1 ab }

  condition:
    any of them
}