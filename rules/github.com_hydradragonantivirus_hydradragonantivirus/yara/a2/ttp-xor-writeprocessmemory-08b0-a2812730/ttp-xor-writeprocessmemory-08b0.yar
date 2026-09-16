rule TTP_XOR_WriteProcessMemory_08b0 {
  strings:
    $key_08b0 = { 5f c2 [2] 6d e0 [2] 6b d5 [2] 45 d5 [2] 7a c9 }

  condition:
    any of them
}