rule TTP_XOR_WriteProcessMemory_5095 {
  strings:
    $key_5095 = { 07 e7 [2] 35 c5 [2] 33 f0 [2] 1d f0 [2] 22 ec }

  condition:
    any of them
}