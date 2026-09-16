rule TTP_XOR_WriteProcessMemory_bd26 {
  strings:
    $key_bd26 = { ea 54 [2] d8 76 [2] de 43 [2] f0 43 [2] cf 5f }

  condition:
    any of them
}