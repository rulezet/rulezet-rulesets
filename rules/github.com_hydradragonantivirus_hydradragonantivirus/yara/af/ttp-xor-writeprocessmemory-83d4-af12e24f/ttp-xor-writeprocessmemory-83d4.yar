rule TTP_XOR_WriteProcessMemory_83d4 {
  strings:
    $key_83d4 = { d4 a6 [2] e6 84 [2] e0 b1 [2] ce b1 [2] f1 ad }

  condition:
    any of them
}