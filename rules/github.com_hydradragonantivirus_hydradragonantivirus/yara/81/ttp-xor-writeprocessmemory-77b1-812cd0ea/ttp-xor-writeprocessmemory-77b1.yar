rule TTP_XOR_WriteProcessMemory_77b1 {
  strings:
    $key_77b1 = { 20 c3 [2] 12 e1 [2] 14 d4 [2] 3a d4 [2] 05 c8 }

  condition:
    any of them
}