rule TTP_XOR_WriteProcessMemory_c395 {
  strings:
    $key_c395 = { 94 e7 [2] a6 c5 [2] a0 f0 [2] 8e f0 [2] b1 ec }

  condition:
    any of them
}