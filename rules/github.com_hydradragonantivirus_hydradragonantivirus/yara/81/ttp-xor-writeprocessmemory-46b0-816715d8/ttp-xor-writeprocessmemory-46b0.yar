rule TTP_XOR_WriteProcessMemory_46b0 {
  strings:
    $key_46b0 = { 11 c2 [2] 23 e0 [2] 25 d5 [2] 0b d5 [2] 34 c9 }

  condition:
    any of them
}