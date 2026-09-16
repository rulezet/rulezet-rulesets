rule TTP_XOR_WriteProcessMemory_8c92 {
  strings:
    $key_8c92 = { db e0 [2] e9 c2 [2] ef f7 [2] c1 f7 [2] fe eb }

  condition:
    any of them
}