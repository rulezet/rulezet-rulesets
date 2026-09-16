rule TTP_XOR_WriteProcessMemory_1295 {
  strings:
    $key_1295 = { 45 e7 [2] 77 c5 [2] 71 f0 [2] 5f f0 [2] 60 ec }

  condition:
    any of them
}