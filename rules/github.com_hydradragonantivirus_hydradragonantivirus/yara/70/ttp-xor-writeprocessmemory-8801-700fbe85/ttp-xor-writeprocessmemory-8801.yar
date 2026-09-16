rule TTP_XOR_WriteProcessMemory_8801 {
  strings:
    $key_8801 = { df 73 [2] ed 51 [2] eb 64 [2] c5 64 [2] fa 78 }

  condition:
    any of them
}