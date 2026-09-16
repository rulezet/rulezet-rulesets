rule TTP_XOR_WriteProcessMemory_e495 {
  strings:
    $key_e495 = { b3 e7 [2] 81 c5 [2] 87 f0 [2] a9 f0 [2] 96 ec }

  condition:
    any of them
}