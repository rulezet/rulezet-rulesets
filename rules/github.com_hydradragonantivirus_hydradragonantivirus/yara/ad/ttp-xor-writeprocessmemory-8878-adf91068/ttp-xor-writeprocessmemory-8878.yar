rule TTP_XOR_WriteProcessMemory_8878 {
  strings:
    $key_8878 = { df 0a [2] ed 28 [2] eb 1d [2] c5 1d [2] fa 01 }

  condition:
    any of them
}