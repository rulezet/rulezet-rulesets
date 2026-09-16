rule TTP_XOR_WriteProcessMemory_6695 {
  strings:
    $key_6695 = { 31 e7 [2] 03 c5 [2] 05 f0 [2] 2b f0 [2] 14 ec }

  condition:
    any of them
}