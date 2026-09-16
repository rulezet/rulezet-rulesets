rule TTP_XOR_WriteProcessMemory_bd50 {
  strings:
    $key_bd50 = { ea 22 [2] d8 00 [2] de 35 [2] f0 35 [2] cf 29 }

  condition:
    any of them
}