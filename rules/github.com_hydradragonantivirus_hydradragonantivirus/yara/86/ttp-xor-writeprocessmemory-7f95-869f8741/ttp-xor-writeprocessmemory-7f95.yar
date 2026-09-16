rule TTP_XOR_WriteProcessMemory_7f95 {
  strings:
    $key_7f95 = { 28 e7 [2] 1a c5 [2] 1c f0 [2] 32 f0 [2] 0d ec }

  condition:
    any of them
}