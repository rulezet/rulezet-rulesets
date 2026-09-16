rule TTP_XOR_WriteProcessMemory_7d95 {
  strings:
    $key_7d95 = { 2a e7 [2] 18 c5 [2] 1e f0 [2] 30 f0 [2] 0f ec }

  condition:
    any of them
}