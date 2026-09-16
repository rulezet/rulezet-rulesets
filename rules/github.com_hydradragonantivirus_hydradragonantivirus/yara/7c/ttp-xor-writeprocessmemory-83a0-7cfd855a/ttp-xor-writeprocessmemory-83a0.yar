rule TTP_XOR_WriteProcessMemory_83a0 {
  strings:
    $key_83a0 = { d4 d2 [2] e6 f0 [2] e0 c5 [2] ce c5 [2] f1 d9 }

  condition:
    any of them
}