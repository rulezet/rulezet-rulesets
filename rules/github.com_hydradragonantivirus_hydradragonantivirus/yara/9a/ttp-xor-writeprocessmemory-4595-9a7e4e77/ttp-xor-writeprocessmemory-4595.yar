rule TTP_XOR_WriteProcessMemory_4595 {
  strings:
    $key_4595 = { 12 e7 [2] 20 c5 [2] 26 f0 [2] 08 f0 [2] 37 ec }

  condition:
    any of them
}