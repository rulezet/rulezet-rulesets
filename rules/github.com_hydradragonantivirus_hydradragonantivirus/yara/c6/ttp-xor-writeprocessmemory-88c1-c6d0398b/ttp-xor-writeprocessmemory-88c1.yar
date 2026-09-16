rule TTP_XOR_WriteProcessMemory_88c1 {
  strings:
    $key_88c1 = { df b3 [2] ed 91 [2] eb a4 [2] c5 a4 [2] fa b8 }

  condition:
    any of them
}