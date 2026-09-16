rule TTP_XOR_WriteProcessMemory_bd62 {
  strings:
    $key_bd62 = { ea 10 [2] d8 32 [2] de 07 [2] f0 07 [2] cf 1b }

  condition:
    any of them
}