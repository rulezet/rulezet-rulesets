rule TTP_XOR_WriteProcessMemory_7b95 {
  strings:
    $key_7b95 = { 2c e7 [2] 1e c5 [2] 18 f0 [2] 36 f0 [2] 09 ec }

  condition:
    any of them
}