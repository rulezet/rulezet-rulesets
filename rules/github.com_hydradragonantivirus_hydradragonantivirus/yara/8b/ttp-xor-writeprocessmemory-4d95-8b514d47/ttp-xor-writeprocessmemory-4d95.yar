rule TTP_XOR_WriteProcessMemory_4d95 {
  strings:
    $key_4d95 = { 1a e7 [2] 28 c5 [2] 2e f0 [2] 00 f0 [2] 3f ec }

  condition:
    any of them
}