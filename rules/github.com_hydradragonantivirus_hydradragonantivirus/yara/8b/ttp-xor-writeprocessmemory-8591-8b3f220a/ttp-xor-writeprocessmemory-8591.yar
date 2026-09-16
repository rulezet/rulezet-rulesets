rule TTP_XOR_WriteProcessMemory_8591 {
  strings:
    $key_8591 = { d2 e3 [2] e0 c1 [2] e6 f4 [2] c8 f4 [2] f7 e8 }

  condition:
    any of them
}