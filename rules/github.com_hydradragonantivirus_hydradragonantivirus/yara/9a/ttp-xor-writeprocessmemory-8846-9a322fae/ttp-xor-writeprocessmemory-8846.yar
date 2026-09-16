rule TTP_XOR_WriteProcessMemory_8846 {
  strings:
    $key_8846 = { df 34 [2] ed 16 [2] eb 23 [2] c5 23 [2] fa 3f }

  condition:
    any of them
}