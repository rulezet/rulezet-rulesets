rule TTP_XOR_WriteProcessMemory_97f8 {
  strings:
    $key_97f8 = { c0 8a [2] f2 a8 [2] f4 9d [2] da 9d [2] e5 81 }

  condition:
    any of them
}