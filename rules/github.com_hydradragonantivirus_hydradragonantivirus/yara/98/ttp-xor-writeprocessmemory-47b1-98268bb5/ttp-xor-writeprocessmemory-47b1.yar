rule TTP_XOR_WriteProcessMemory_47b1 {
  strings:
    $key_47b1 = { 10 c3 [2] 22 e1 [2] 24 d4 [2] 0a d4 [2] 35 c8 }

  condition:
    any of them
}