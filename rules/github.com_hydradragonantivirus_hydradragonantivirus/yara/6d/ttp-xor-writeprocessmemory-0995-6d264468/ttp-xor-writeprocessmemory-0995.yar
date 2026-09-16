rule TTP_XOR_WriteProcessMemory_0995 {
  strings:
    $key_0995 = { 5e e7 [2] 6c c5 [2] 6a f0 [2] 44 f0 [2] 7b ec }

  condition:
    any of them
}