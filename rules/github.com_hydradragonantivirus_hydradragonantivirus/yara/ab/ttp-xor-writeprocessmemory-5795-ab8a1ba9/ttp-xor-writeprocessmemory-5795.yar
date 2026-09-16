rule TTP_XOR_WriteProcessMemory_5795 {
  strings:
    $key_5795 = { 00 e7 [2] 32 c5 [2] 34 f0 [2] 1a f0 [2] 25 ec }

  condition:
    any of them
}