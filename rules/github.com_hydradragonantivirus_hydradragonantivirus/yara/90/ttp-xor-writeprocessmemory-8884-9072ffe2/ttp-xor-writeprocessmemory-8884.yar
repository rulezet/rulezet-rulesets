rule TTP_XOR_WriteProcessMemory_8884 {
  strings:
    $key_8884 = { df f6 [2] ed d4 [2] eb e1 [2] c5 e1 [2] fa fd }

  condition:
    any of them
}