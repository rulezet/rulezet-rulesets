rule TTP_XOR_WriteProcessMemory_8cd6 {
  strings:
    $key_8cd6 = { db a4 [2] e9 86 [2] ef b3 [2] c1 b3 [2] fe af }

  condition:
    any of them
}