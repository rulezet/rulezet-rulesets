rule TTP_XOR_WriteProcessMemory_8c95 {
  strings:
    $key_8c95 = { db e7 [2] e9 c5 [2] ef f0 [2] c1 f0 [2] fe ec }

  condition:
    any of them
}