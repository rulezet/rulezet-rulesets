rule TTP_XOR_WriteProcessMemory_7195 {
  strings:
    $key_7195 = { 26 e7 [2] 14 c5 [2] 12 f0 [2] 3c f0 [2] 03 ec }

  condition:
    any of them
}