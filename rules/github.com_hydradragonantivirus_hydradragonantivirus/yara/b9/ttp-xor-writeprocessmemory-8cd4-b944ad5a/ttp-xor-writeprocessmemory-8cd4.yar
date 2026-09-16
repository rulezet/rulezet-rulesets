rule TTP_XOR_WriteProcessMemory_8cd4 {
  strings:
    $key_8cd4 = { db a6 [2] e9 84 [2] ef b1 [2] c1 b1 [2] fe ad }

  condition:
    any of them
}