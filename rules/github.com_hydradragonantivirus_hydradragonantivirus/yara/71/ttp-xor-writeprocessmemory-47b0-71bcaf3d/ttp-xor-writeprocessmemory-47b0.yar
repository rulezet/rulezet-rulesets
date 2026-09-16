rule TTP_XOR_WriteProcessMemory_47b0 {
  strings:
    $key_47b0 = { 10 c2 [2] 22 e0 [2] 24 d5 [2] 0a d5 [2] 35 c9 }

  condition:
    any of them
}