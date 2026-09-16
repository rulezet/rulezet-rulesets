rule TTP_XOR_WriteProcessMemory_0db0 {
  strings:
    $key_0db0 = { 5a c2 [2] 68 e0 [2] 6e d5 [2] 40 d5 [2] 7f c9 }

  condition:
    any of them
}