rule TTP_XOR_WriteProcessMemory_97d5 {
  strings:
    $key_97d5 = { c0 a7 [2] f2 85 [2] f4 b0 [2] da b0 [2] e5 ac }

  condition:
    any of them
}