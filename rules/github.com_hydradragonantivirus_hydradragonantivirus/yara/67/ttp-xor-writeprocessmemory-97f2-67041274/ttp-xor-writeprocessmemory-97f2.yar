rule TTP_XOR_WriteProcessMemory_97f2 {
  strings:
    $key_97f2 = { c0 80 [2] f2 a2 [2] f4 97 [2] da 97 [2] e5 8b }

  condition:
    any of them
}