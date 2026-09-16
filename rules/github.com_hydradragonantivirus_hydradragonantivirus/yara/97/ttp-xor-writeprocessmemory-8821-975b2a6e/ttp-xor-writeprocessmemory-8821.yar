rule TTP_XOR_WriteProcessMemory_8821 {
  strings:
    $key_8821 = { df 53 [2] ed 71 [2] eb 44 [2] c5 44 [2] fa 58 }

  condition:
    any of them
}