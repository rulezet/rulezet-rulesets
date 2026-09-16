rule TTP_XOR_WriteProcessMemory_1a95 {
  strings:
    $key_1a95 = { 4d e7 [2] 7f c5 [2] 79 f0 [2] 57 f0 [2] 68 ec }

  condition:
    any of them
}