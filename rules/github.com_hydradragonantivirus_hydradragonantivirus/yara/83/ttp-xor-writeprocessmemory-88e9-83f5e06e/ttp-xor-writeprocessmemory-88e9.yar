rule TTP_XOR_WriteProcessMemory_88e9 {
  strings:
    $key_88e9 = { df 9b [2] ed b9 [2] eb 8c [2] c5 8c [2] fa 90 }

  condition:
    any of them
}