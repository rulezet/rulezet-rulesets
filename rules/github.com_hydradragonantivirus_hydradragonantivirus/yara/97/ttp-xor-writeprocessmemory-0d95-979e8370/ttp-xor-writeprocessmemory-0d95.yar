rule TTP_XOR_WriteProcessMemory_0d95 {
  strings:
    $key_0d95 = { 5a e7 [2] 68 c5 [2] 6e f0 [2] 40 f0 [2] 7f ec }

  condition:
    any of them
}