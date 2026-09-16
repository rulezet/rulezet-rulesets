rule TTP_XOR_WriteProcessMemory_1595 {
  strings:
    $key_1595 = { 42 e7 [2] 70 c5 [2] 76 f0 [2] 58 f0 [2] 67 ec }

  condition:
    any of them
}