rule TTP_XOR_WriteProcessMemory_e095 {
  strings:
    $key_e095 = { b7 e7 [2] 85 c5 [2] 83 f0 [2] ad f0 [2] 92 ec }

  condition:
    any of them
}