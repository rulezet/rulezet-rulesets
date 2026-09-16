rule TTP_XOR_WriteProcessMemory_8b95 {
  strings:
    $key_8b95 = { dc e7 [2] ee c5 [2] e8 f0 [2] c6 f0 [2] f9 ec }

  condition:
    any of them
}