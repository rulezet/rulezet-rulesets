rule TTP_XOR_WriteProcessMemory_8860 {
  strings:
    $key_8860 = { df 12 [2] ed 30 [2] eb 05 [2] c5 05 [2] fa 19 }

  condition:
    any of them
}