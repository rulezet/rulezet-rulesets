rule TTP_XOR_WriteProcessMemory_97a4 {
  strings:
    $key_97a4 = { c0 d6 [2] f2 f4 [2] f4 c1 [2] da c1 [2] e5 dd }

  condition:
    any of them
}