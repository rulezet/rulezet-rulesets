rule TTP_XOR_WriteProcessMemory_8853 {
  strings:
    $key_8853 = { df 21 [2] ed 03 [2] eb 36 [2] c5 36 [2] fa 2a }

  condition:
    any of them
}