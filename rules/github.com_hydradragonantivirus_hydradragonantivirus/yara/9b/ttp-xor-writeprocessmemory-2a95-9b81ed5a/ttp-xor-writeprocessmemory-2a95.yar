rule TTP_XOR_WriteProcessMemory_2a95 {
  strings:
    $key_2a95 = { 7d e7 [2] 4f c5 [2] 49 f0 [2] 67 f0 [2] 58 ec }

  condition:
    any of them
}