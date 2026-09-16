rule TTP_XOR_WriteProcessMemory_83a7 {
  strings:
    $key_83a7 = { d4 d5 [2] e6 f7 [2] e0 c2 [2] ce c2 [2] f1 de }

  condition:
    any of them
}