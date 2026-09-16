rule TTP_XOR_WriteProcessMemory_4a95 {
  strings:
    $key_4a95 = { 1d e7 [2] 2f c5 [2] 29 f0 [2] 07 f0 [2] 38 ec }

  condition:
    any of them
}