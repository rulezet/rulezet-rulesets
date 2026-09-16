rule TTP_XOR_WriteProcessMemory_8874 {
  strings:
    $key_8874 = { df 06 [2] ed 24 [2] eb 11 [2] c5 11 [2] fa 0d }

  condition:
    any of them
}