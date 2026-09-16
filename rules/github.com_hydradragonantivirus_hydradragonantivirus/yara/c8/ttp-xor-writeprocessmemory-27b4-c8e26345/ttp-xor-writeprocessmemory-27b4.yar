rule TTP_XOR_WriteProcessMemory_27b4 {
  strings:
    $key_27b4 = { 70 c6 [2] 42 e4 [2] 44 d1 [2] 6a d1 [2] 55 cd }

  condition:
    any of them
}