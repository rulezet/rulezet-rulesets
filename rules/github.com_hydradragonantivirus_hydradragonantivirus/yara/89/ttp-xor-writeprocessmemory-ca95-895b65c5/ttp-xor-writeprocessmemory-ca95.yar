rule TTP_XOR_WriteProcessMemory_ca95 {
  strings:
    $key_ca95 = { 9d e7 [2] af c5 [2] a9 f0 [2] 87 f0 [2] b8 ec }

  condition:
    any of them
}