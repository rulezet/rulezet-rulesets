rule TTP_XOR_WriteProcessMemory_8855 {
  strings:
    $key_8855 = { df 27 [2] ed 05 [2] eb 30 [2] c5 30 [2] fa 2c }

  condition:
    any of them
}