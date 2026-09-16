rule TTP_XOR_WriteProcessMemory_2295 {
  strings:
    $key_2295 = { 75 e7 [2] 47 c5 [2] 41 f0 [2] 6f f0 [2] 50 ec }

  condition:
    any of them
}