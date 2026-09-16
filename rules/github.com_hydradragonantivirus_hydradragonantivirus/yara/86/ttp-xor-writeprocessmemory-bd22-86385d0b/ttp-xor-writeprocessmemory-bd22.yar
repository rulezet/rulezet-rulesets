rule TTP_XOR_WriteProcessMemory_bd22 {
  strings:
    $key_bd22 = { ea 50 [2] d8 72 [2] de 47 [2] f0 47 [2] cf 5b }

  condition:
    any of them
}