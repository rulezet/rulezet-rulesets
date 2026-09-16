rule TTP_XOR_WriteProcessMemory_7795 {
  strings:
    $key_7795 = { 20 e7 [2] 12 c5 [2] 14 f0 [2] 3a f0 [2] 05 ec }

  condition:
    any of them
}