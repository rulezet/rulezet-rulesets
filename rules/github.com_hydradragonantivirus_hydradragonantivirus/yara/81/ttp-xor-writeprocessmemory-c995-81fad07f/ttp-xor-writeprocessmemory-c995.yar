rule TTP_XOR_WriteProcessMemory_c995 {
  strings:
    $key_c995 = { 9e e7 [2] ac c5 [2] aa f0 [2] 84 f0 [2] bb ec }

  condition:
    any of them
}