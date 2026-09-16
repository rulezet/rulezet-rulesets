rule TTP_XOR_WriteProcessMemory_6d95 {
  strings:
    $key_6d95 = { 3a e7 [2] 08 c5 [2] 0e f0 [2] 20 f0 [2] 1f ec }

  condition:
    any of them
}