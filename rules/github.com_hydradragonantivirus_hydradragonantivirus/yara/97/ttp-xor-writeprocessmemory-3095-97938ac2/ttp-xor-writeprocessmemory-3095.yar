rule TTP_XOR_WriteProcessMemory_3095 {
  strings:
    $key_3095 = { 67 e7 [2] 55 c5 [2] 53 f0 [2] 7d f0 [2] 42 ec }

  condition:
    any of them
}