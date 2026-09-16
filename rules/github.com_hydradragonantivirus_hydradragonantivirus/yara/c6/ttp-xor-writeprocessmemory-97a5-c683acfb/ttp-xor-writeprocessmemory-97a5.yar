rule TTP_XOR_WriteProcessMemory_97a5 {
  strings:
    $key_97a5 = { c0 d7 [2] f2 f5 [2] f4 c0 [2] da c0 [2] e5 dc }

  condition:
    any of them
}