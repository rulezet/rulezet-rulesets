rule TTP_XOR_WriteProcessMemory_8886 {
  strings:
    $key_8886 = { df f4 [2] ed d6 [2] eb e3 [2] c5 e3 [2] fa ff }

  condition:
    any of them
}