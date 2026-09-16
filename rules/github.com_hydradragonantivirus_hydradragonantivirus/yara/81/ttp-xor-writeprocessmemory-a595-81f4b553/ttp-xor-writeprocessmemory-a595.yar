rule TTP_XOR_WriteProcessMemory_a595 {
  strings:
    $key_a595 = { f2 e7 [2] c0 c5 [2] c6 f0 [2] e8 f0 [2] d7 ec }

  condition:
    any of them
}