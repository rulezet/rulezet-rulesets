rule TTP_XOR_WriteProcessMemory_7a95 {
  strings:
    $key_7a95 = { 2d e7 [2] 1f c5 [2] 19 f0 [2] 37 f0 [2] 08 ec }

  condition:
    any of them
}