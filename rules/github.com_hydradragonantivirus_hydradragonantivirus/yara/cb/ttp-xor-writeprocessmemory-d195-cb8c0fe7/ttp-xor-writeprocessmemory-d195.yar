rule TTP_XOR_WriteProcessMemory_d195 {
  strings:
    $key_d195 = { 86 e7 [2] b4 c5 [2] b2 f0 [2] 9c f0 [2] a3 ec }

  condition:
    any of them
}