rule TTP_XOR_WriteProcessMemory_8877 {
  strings:
    $key_8877 = { df 05 [2] ed 27 [2] eb 12 [2] c5 12 [2] fa 0e }

  condition:
    any of them
}