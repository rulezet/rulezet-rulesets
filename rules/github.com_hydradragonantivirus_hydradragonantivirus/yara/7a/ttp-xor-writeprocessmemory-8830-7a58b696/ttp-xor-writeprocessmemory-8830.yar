rule TTP_XOR_WriteProcessMemory_8830 {
  strings:
    $key_8830 = { df 42 [2] ed 60 [2] eb 55 [2] c5 55 [2] fa 49 }

  condition:
    any of them
}