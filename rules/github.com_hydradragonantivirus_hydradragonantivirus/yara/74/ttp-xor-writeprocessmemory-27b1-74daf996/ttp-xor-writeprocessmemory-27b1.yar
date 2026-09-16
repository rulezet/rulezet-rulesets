rule TTP_XOR_WriteProcessMemory_27b1 {
  strings:
    $key_27b1 = { 70 c3 [2] 42 e1 [2] 44 d4 [2] 6a d4 [2] 55 c8 }

  condition:
    any of them
}