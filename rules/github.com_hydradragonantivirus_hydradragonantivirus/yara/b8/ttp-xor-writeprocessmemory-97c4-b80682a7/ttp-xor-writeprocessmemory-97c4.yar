rule TTP_XOR_WriteProcessMemory_97c4 {
  strings:
    $key_97c4 = { c0 b6 [2] f2 94 [2] f4 a1 [2] da a1 [2] e5 bd }

  condition:
    any of them
}