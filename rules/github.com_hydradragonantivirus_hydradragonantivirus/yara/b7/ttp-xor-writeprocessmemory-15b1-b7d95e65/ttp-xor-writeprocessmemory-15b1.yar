rule TTP_XOR_WriteProcessMemory_15b1 {
  strings:
    $key_15b1 = { 42 c3 [2] 70 e1 [2] 76 d4 [2] 58 d4 [2] 67 c8 }

  condition:
    any of them
}