rule TTP_XOR_WriteProcessMemory_8cd2 {
  strings:
    $key_8cd2 = { db a0 [2] e9 82 [2] ef b7 [2] c1 b7 [2] fe ab }

  condition:
    any of them
}