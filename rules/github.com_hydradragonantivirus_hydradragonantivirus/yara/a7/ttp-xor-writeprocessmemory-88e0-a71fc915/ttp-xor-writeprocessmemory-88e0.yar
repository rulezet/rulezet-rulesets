rule TTP_XOR_WriteProcessMemory_88e0 {
  strings:
    $key_88e0 = { df 92 [2] ed b0 [2] eb 85 [2] c5 85 [2] fa 99 }

  condition:
    any of them
}