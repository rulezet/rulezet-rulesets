rule TTP_XOR_WriteProcessMemory_97d4 {
  strings:
    $key_97d4 = { c0 a6 [2] f2 84 [2] f4 b1 [2] da b1 [2] e5 ad }

  condition:
    any of them
}