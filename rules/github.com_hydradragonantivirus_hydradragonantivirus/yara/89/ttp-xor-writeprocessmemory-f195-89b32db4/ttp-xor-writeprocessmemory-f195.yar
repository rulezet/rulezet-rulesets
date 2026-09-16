rule TTP_XOR_WriteProcessMemory_f195 {
  strings:
    $key_f195 = { a6 e7 [2] 94 c5 [2] 92 f0 [2] bc f0 [2] 83 ec }

  condition:
    any of them
}