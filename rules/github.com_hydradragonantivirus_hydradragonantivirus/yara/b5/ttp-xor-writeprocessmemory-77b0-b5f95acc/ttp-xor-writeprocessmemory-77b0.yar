rule TTP_XOR_WriteProcessMemory_77b0 {
  strings:
    $key_77b0 = { 20 c2 [2] 12 e0 [2] 14 d5 [2] 3a d5 [2] 05 c9 }

  condition:
    any of them
}