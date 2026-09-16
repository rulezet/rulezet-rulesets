rule TTP_XOR_WriteProcessMemory_3795 {
  strings:
    $key_3795 = { 60 e7 [2] 52 c5 [2] 54 f0 [2] 7a f0 [2] 45 ec }

  condition:
    any of them
}