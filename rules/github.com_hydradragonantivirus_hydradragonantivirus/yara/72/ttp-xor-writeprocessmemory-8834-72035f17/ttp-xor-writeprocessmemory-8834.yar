rule TTP_XOR_WriteProcessMemory_8834 {
  strings:
    $key_8834 = { df 46 [2] ed 64 [2] eb 51 [2] c5 51 [2] fa 4d }

  condition:
    any of them
}