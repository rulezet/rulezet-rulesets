rule TTP_XOR_WriteProcessMemory_e295 {
  strings:
    $key_e295 = { b5 e7 [2] 87 c5 [2] 81 f0 [2] af f0 [2] 90 ec }

  condition:
    any of them
}