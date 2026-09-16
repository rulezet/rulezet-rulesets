rule TTP_XOR_WriteProcessMemory_f395 {
  strings:
    $key_f395 = { a4 e7 [2] 96 c5 [2] 90 f0 [2] be f0 [2] 81 ec }

  condition:
    any of them
}