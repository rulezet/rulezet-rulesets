rule TTP_XOR_WriteProcessMemory_4295 {
  strings:
    $key_4295 = { 15 e7 [2] 27 c5 [2] 21 f0 [2] 0f f0 [2] 30 ec }

  condition:
    any of them
}