rule TTP_XOR_WriteProcessMemory_e0b0 {
  strings:
    $key_e0b0 = { b7 c2 [2] 85 e0 [2] 83 d5 [2] ad d5 [2] 92 c9 }

  condition:
    any of them
}