rule TTP_XOR_WriteProcessMemory_97d1 {
  strings:
    $key_97d1 = { c0 a3 [2] f2 81 [2] f4 b4 [2] da b4 [2] e5 a8 }

  condition:
    any of them
}