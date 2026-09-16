rule TTP_XOR_WriteProcessMemory_8c90 {
  strings:
    $key_8c90 = { db e2 [2] e9 c0 [2] ef f5 [2] c1 f5 [2] fe e9 }

  condition:
    any of them
}