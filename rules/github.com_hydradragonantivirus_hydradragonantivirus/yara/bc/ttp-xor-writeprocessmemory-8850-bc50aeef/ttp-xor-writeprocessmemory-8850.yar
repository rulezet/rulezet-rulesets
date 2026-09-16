rule TTP_XOR_WriteProcessMemory_8850 {
  strings:
    $key_8850 = { df 22 [2] ed 00 [2] eb 35 [2] c5 35 [2] fa 29 }

  condition:
    any of them
}