rule TTP_XOR_WriteProcessMemory_8195 {
  strings:
    $key_8195 = { d6 e7 [2] e4 c5 [2] e2 f0 [2] cc f0 [2] f3 ec }

  condition:
    any of them
}