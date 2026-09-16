rule TTP_XOR_WriteProcessMemory_4995 {
  strings:
    $key_4995 = { 1e e7 [2] 2c c5 [2] 2a f0 [2] 04 f0 [2] 3b ec }

  condition:
    any of them
}