rule TTP_XOR_WriteProcessMemory_bd95 {
  strings:
    $key_bd95 = { ea e7 [2] d8 c5 [2] de f0 [2] f0 f0 [2] cf ec }

  condition:
    any of them
}