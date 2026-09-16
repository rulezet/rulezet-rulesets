rule TTP_XOR_WriteProcessMemory_8833 {
  strings:
    $key_8833 = { df 41 [2] ed 63 [2] eb 56 [2] c5 56 [2] fa 4a }

  condition:
    any of them
}