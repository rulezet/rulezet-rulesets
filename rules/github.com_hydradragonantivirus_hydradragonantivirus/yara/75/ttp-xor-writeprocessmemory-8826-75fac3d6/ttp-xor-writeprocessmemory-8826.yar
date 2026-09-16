rule TTP_XOR_WriteProcessMemory_8826 {
  strings:
    $key_8826 = { df 54 [2] ed 76 [2] eb 43 [2] c5 43 [2] fa 5f }

  condition:
    any of them
}