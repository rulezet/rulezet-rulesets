rule TTP_XOR_WriteProcessMemory_6195 {
  strings:
    $key_6195 = { 36 e7 [2] 04 c5 [2] 02 f0 [2] 2c f0 [2] 13 ec }

  condition:
    any of them
}