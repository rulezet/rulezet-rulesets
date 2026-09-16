rule TTP_XOR_WriteProcessMemory_88d5 {
  strings:
    $key_88d5 = { df a7 [2] ed 85 [2] eb b0 [2] c5 b0 [2] fa ac }

  condition:
    any of them
}