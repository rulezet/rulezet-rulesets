rule TTP_XOR_WriteProcessMemory_c495 {
  strings:
    $key_c495 = { 93 e7 [2] a1 c5 [2] a7 f0 [2] 89 f0 [2] b6 ec }

  condition:
    any of them
}