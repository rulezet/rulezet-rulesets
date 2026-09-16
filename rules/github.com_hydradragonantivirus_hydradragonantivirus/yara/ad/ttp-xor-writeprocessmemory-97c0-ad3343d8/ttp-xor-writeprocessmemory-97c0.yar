rule TTP_XOR_WriteProcessMemory_97c0 {
  strings:
    $key_97c0 = { c0 b2 [2] f2 90 [2] f4 a5 [2] da a5 [2] e5 b9 }

  condition:
    any of them
}