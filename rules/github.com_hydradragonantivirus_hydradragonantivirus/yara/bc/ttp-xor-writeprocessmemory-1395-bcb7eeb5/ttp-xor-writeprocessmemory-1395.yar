rule TTP_XOR_WriteProcessMemory_1395 {
  strings:
    $key_1395 = { 44 e7 [2] 76 c5 [2] 70 f0 [2] 5e f0 [2] 61 ec }

  condition:
    any of them
}