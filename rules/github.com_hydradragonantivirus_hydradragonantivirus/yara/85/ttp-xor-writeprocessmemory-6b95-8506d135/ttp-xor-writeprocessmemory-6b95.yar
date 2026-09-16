rule TTP_XOR_WriteProcessMemory_6b95 {
  strings:
    $key_6b95 = { 3c e7 [2] 0e c5 [2] 08 f0 [2] 26 f0 [2] 19 ec }

  condition:
    any of them
}