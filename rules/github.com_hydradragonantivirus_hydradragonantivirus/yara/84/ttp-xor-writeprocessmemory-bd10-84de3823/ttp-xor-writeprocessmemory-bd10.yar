rule TTP_XOR_WriteProcessMemory_bd10 {
  strings:
    $key_bd10 = { ea 62 [2] d8 40 [2] de 75 [2] f0 75 [2] cf 69 }

  condition:
    any of them
}