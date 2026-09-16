rule TTP_XOR_WriteProcessMemory_97f3 {
  strings:
    $key_97f3 = { c0 81 [2] f2 a3 [2] f4 96 [2] da 96 [2] e5 8a }

  condition:
    any of them
}