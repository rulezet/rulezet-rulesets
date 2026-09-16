rule TTP_XOR_WriteProcessMemory_5295 {
  strings:
    $key_5295 = { 05 e7 [2] 37 c5 [2] 31 f0 [2] 1f f0 [2] 20 ec }

  condition:
    any of them
}