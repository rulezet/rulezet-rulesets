rule TTP_XOR_WriteProcessMemory_21b1 {
  strings:
    $key_21b1 = { 76 c3 [2] 44 e1 [2] 42 d4 [2] 6c d4 [2] 53 c8 }

  condition:
    any of them
}