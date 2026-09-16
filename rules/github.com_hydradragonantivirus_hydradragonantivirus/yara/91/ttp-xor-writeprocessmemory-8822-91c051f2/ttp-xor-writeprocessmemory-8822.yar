rule TTP_XOR_WriteProcessMemory_8822 {
  strings:
    $key_8822 = { df 50 [2] ed 72 [2] eb 47 [2] c5 47 [2] fa 5b }

  condition:
    any of them
}