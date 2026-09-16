rule TTP_XOR_WriteProcessMemory_8861 {
  strings:
    $key_8861 = { df 13 [2] ed 31 [2] eb 04 [2] c5 04 [2] fa 18 }

  condition:
    any of them
}