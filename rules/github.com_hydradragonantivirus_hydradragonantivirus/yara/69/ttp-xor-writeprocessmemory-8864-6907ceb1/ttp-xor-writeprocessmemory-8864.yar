rule TTP_XOR_WriteProcessMemory_8864 {
  strings:
    $key_8864 = { df 16 [2] ed 34 [2] eb 01 [2] c5 01 [2] fa 1d }

  condition:
    any of them
}