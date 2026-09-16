rule TTP_XOR_WriteProcessMemory_8810 {
  strings:
    $key_8810 = { df 62 [2] ed 40 [2] eb 75 [2] c5 75 [2] fa 69 }

  condition:
    any of them
}