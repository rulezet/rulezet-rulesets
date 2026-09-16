rule TTP_XOR_WriteProcessMemory_8879 {
  strings:
    $key_8879 = { df 0b [2] ed 29 [2] eb 1c [2] c5 1c [2] fa 00 }

  condition:
    any of them
}