rule TTP_XOR_WriteProcessMemory_2e95 {
  strings:
    $key_2e95 = { 79 e7 [2] 4b c5 [2] 4d f0 [2] 63 f0 [2] 5c ec }

  condition:
    any of them
}