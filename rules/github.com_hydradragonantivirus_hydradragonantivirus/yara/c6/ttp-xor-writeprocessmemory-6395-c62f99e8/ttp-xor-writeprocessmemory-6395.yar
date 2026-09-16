rule TTP_XOR_WriteProcessMemory_6395 {
  strings:
    $key_6395 = { 34 e7 [2] 06 c5 [2] 00 f0 [2] 2e f0 [2] 11 ec }

  condition:
    any of them
}