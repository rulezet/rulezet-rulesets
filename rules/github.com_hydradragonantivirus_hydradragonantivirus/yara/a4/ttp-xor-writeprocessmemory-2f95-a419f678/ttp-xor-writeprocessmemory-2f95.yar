rule TTP_XOR_WriteProcessMemory_2f95 {
  strings:
    $key_2f95 = { 78 e7 [2] 4a c5 [2] 4c f0 [2] 62 f0 [2] 5d ec }

  condition:
    any of them
}