rule TTP_XOR_WriteProcessMemory_3db0 {
  strings:
    $key_3db0 = { 6a c2 [2] 58 e0 [2] 5e d5 [2] 70 d5 [2] 4f c9 }

  condition:
    any of them
}