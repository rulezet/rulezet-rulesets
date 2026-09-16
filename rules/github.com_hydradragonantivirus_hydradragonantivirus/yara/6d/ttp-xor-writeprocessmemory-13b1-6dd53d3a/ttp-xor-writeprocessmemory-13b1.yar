rule TTP_XOR_WriteProcessMemory_13b1 {
  strings:
    $key_13b1 = { 44 c3 [2] 76 e1 [2] 70 d4 [2] 5e d4 [2] 61 c8 }

  condition:
    any of them
}