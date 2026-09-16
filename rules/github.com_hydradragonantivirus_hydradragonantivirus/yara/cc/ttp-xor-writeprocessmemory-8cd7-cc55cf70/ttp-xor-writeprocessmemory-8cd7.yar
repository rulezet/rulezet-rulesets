rule TTP_XOR_WriteProcessMemory_8cd7 {
  strings:
    $key_8cd7 = { db a5 [2] e9 87 [2] ef b2 [2] c1 b2 [2] fe ae }

  condition:
    any of them
}