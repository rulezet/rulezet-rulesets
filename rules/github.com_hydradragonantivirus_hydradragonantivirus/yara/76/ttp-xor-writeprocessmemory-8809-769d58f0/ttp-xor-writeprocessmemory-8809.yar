rule TTP_XOR_WriteProcessMemory_8809 {
  strings:
    $key_8809 = { df 7b [2] ed 59 [2] eb 6c [2] c5 6c [2] fa 70 }

  condition:
    any of them
}