rule TTP_XOR_WriteProcessMemory_1495 {
  strings:
    $key_1495 = { 43 e7 [2] 71 c5 [2] 77 f0 [2] 59 f0 [2] 66 ec }

  condition:
    any of them
}