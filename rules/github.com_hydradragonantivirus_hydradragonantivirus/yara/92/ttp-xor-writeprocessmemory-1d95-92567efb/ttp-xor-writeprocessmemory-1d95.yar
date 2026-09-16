rule TTP_XOR_WriteProcessMemory_1d95 {
  strings:
    $key_1d95 = { 4a e7 [2] 78 c5 [2] 7e f0 [2] 50 f0 [2] 6f ec }

  condition:
    any of them
}