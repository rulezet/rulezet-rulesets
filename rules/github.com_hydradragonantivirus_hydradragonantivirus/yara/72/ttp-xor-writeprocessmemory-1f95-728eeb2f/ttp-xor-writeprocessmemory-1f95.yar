rule TTP_XOR_WriteProcessMemory_1f95 {
  strings:
    $key_1f95 = { 48 e7 [2] 7a c5 [2] 7c f0 [2] 52 f0 [2] 6d ec }

  condition:
    any of them
}