rule TTP_XOR_WriteProcessMemory_88d7 {
  strings:
    $key_88d7 = { df a5 [2] ed 87 [2] eb b2 [2] c5 b2 [2] fa ae }

  condition:
    any of them
}