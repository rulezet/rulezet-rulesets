rule TTP_XOR_WriteProcessMemory_8820 {
  strings:
    $key_8820 = { df 52 [2] ed 70 [2] eb 45 [2] c5 45 [2] fa 59 }

  condition:
    any of them
}