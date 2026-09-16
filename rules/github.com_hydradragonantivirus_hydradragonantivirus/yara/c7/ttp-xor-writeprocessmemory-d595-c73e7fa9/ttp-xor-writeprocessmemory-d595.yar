rule TTP_XOR_WriteProcessMemory_d595 {
  strings:
    $key_d595 = { 82 e7 [2] b0 c5 [2] b6 f0 [2] 98 f0 [2] a7 ec }

  condition:
    any of them
}