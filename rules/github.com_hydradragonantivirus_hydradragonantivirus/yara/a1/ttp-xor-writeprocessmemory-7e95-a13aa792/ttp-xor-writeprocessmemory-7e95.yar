rule TTP_XOR_WriteProcessMemory_7e95 {
  strings:
    $key_7e95 = { 29 e7 [2] 1b c5 [2] 1d f0 [2] 33 f0 [2] 0c ec }

  condition:
    any of them
}