rule TTP_XOR_WriteProcessMemory_8871 {
  strings:
    $key_8871 = { df 03 [2] ed 21 [2] eb 14 [2] c5 14 [2] fa 08 }

  condition:
    any of them
}