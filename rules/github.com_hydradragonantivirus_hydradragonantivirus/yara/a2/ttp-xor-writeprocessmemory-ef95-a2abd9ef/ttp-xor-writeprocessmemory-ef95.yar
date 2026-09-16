rule TTP_XOR_WriteProcessMemory_ef95 {
  strings:
    $key_ef95 = { b8 e7 [2] 8a c5 [2] 8c f0 [2] a2 f0 [2] 9d ec }

  condition:
    any of them
}