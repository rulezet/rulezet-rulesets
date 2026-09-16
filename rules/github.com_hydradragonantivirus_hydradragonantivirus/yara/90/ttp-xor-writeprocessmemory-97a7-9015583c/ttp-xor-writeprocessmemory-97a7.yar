rule TTP_XOR_WriteProcessMemory_97a7 {
  strings:
    $key_97a7 = { c0 d5 [2] f2 f7 [2] f4 c2 [2] da c2 [2] e5 de }

  condition:
    any of them
}