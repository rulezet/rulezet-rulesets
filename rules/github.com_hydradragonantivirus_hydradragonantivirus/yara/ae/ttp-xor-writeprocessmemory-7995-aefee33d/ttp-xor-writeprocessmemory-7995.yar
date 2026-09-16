rule TTP_XOR_WriteProcessMemory_7995 {
  strings:
    $key_7995 = { 2e e7 [2] 1c c5 [2] 1a f0 [2] 34 f0 [2] 0b ec }

  condition:
    any of them
}