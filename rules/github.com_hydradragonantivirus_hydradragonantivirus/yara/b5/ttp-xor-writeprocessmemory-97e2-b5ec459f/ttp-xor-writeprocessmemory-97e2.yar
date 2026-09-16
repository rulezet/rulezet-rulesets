rule TTP_XOR_WriteProcessMemory_97e2 {
  strings:
    $key_97e2 = { c0 90 [2] f2 b2 [2] f4 87 [2] da 87 [2] e5 9b }

  condition:
    any of them
}