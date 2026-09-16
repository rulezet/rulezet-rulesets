rule TTP_XOR_WriteProcessMemory_0395 {
  strings:
    $key_0395 = { 54 e7 [2] 66 c5 [2] 60 f0 [2] 4e f0 [2] 71 ec }

  condition:
    any of them
}