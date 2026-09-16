rule TTP_XOR_WriteProcessMemory_5a95 {
  strings:
    $key_5a95 = { 0d e7 [2] 3f c5 [2] 39 f0 [2] 17 f0 [2] 28 ec }

  condition:
    any of them
}