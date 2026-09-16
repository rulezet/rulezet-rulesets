rule TTP_XOR_WriteProcessMemory_88c4 {
  strings:
    $key_88c4 = { df b6 [2] ed 94 [2] eb a1 [2] c5 a1 [2] fa bd }

  condition:
    any of them
}