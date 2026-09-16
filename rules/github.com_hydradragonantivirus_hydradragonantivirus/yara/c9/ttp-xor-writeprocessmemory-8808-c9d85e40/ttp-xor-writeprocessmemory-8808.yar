rule TTP_XOR_WriteProcessMemory_8808 {
  strings:
    $key_8808 = { df 7a [2] ed 58 [2] eb 6d [2] c5 6d [2] fa 71 }

  condition:
    any of them
}