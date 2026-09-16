rule TTP_XOR_WriteProcessMemory_97a2 {
  strings:
    $key_97a2 = { c0 d0 [2] f2 f2 [2] f4 c7 [2] da c7 [2] e5 db }

  condition:
    any of them
}