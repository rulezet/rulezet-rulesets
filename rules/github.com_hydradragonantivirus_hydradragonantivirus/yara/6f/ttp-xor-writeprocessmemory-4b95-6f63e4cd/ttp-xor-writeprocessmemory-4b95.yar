rule TTP_XOR_WriteProcessMemory_4b95 {
  strings:
    $key_4b95 = { 1c e7 [2] 2e c5 [2] 28 f0 [2] 06 f0 [2] 39 ec }

  condition:
    any of them
}