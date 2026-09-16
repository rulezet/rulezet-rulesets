rule TTP_XOR_WriteProcessMemory_8cd0 {
  strings:
    $key_8cd0 = { db a2 [2] e9 80 [2] ef b5 [2] c1 b5 [2] fe a9 }

  condition:
    any of them
}