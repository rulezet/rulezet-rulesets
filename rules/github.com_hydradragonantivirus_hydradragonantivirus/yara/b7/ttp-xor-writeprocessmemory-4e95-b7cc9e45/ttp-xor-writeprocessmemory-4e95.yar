rule TTP_XOR_WriteProcessMemory_4e95 {
  strings:
    $key_4e95 = { 19 e7 [2] 2b c5 [2] 2d f0 [2] 03 f0 [2] 3c ec }

  condition:
    any of them
}