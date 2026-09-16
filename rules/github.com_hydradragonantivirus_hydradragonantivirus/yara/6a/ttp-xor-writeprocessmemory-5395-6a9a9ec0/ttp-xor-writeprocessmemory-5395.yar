rule TTP_XOR_WriteProcessMemory_5395 {
  strings:
    $key_5395 = { 04 e7 [2] 36 c5 [2] 30 f0 [2] 1e f0 [2] 21 ec }

  condition:
    any of them
}