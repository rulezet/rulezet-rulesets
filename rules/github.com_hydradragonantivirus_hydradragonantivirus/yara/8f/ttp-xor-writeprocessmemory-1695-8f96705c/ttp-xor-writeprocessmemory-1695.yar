rule TTP_XOR_WriteProcessMemory_1695 {
  strings:
    $key_1695 = { 41 e7 [2] 73 c5 [2] 75 f0 [2] 5b f0 [2] 64 ec }

  condition:
    any of them
}