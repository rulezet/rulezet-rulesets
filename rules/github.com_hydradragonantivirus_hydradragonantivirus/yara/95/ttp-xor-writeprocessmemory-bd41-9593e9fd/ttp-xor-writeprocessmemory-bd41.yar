rule TTP_XOR_WriteProcessMemory_bd41 {
  strings:
    $key_bd41 = { ea 33 [2] d8 11 [2] de 24 [2] f0 24 [2] cf 38 }

  condition:
    any of them
}