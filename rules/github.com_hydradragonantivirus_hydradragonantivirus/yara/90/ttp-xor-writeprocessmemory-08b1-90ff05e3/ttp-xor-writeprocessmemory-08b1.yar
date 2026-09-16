rule TTP_XOR_WriteProcessMemory_08b1 {
  strings:
    $key_08b1 = { 5f c3 [2] 6d e1 [2] 6b d4 [2] 45 d4 [2] 7a c8 }

  condition:
    any of them
}