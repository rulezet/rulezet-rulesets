rule TTP_XOR_WriteProcessMemory_97e7 {
  strings:
    $key_97e7 = { c0 95 [2] f2 b7 [2] f4 82 [2] da 82 [2] e5 9e }

  condition:
    any of them
}