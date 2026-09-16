rule TTP_XOR_WriteProcessMemory_0db1 {
  strings:
    $key_0db1 = { 5a c3 [2] 68 e1 [2] 6e d4 [2] 40 d4 [2] 7f c8 }

  condition:
    any of them
}