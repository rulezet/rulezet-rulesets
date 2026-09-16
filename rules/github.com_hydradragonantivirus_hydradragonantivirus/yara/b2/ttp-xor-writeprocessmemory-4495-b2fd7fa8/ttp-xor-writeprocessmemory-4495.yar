rule TTP_XOR_WriteProcessMemory_4495 {
  strings:
    $key_4495 = { 13 e7 [2] 21 c5 [2] 27 f0 [2] 09 f0 [2] 36 ec }

  condition:
    any of them
}