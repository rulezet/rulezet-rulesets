rule TTP_XOR_WriteProcessMemory_8842 {
  strings:
    $key_8842 = { df 30 [2] ed 12 [2] eb 27 [2] c5 27 [2] fa 3b }

  condition:
    any of them
}