rule TTP_XOR_WriteProcessMemory_ed95 {
  strings:
    $key_ed95 = { ba e7 [2] 88 c5 [2] 8e f0 [2] a0 f0 [2] 9f ec }

  condition:
    any of them
}