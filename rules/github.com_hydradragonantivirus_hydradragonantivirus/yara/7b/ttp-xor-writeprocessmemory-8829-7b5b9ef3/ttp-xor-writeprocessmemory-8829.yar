rule TTP_XOR_WriteProcessMemory_8829 {
  strings:
    $key_8829 = { df 5b [2] ed 79 [2] eb 4c [2] c5 4c [2] fa 50 }

  condition:
    any of them
}