rule TTP_XOR_WriteProcessMemory_d395 {
  strings:
    $key_d395 = { 84 e7 [2] b6 c5 [2] b0 f0 [2] 9e f0 [2] a1 ec }

  condition:
    any of them
}