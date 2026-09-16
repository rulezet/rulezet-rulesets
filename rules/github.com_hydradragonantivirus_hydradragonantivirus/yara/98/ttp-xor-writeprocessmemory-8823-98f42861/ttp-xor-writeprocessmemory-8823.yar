rule TTP_XOR_WriteProcessMemory_8823 {
  strings:
    $key_8823 = { df 51 [2] ed 73 [2] eb 46 [2] c5 46 [2] fa 5a }

  condition:
    any of them
}