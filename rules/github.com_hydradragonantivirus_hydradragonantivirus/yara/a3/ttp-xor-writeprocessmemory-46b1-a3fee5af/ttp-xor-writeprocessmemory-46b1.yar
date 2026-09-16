rule TTP_XOR_WriteProcessMemory_46b1 {
  strings:
    $key_46b1 = { 11 c3 [2] 23 e1 [2] 25 d4 [2] 0b d4 [2] 34 c8 }

  condition:
    any of them
}