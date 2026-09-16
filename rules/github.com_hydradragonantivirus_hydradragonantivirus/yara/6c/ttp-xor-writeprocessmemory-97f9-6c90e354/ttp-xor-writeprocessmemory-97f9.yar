rule TTP_XOR_WriteProcessMemory_97f9 {
  strings:
    $key_97f9 = { c0 8b [2] f2 a9 [2] f4 9c [2] da 9c [2] e5 80 }

  condition:
    any of them
}