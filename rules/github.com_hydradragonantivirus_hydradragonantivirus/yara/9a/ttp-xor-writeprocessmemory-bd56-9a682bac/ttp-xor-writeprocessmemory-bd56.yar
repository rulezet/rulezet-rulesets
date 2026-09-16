rule TTP_XOR_WriteProcessMemory_bd56 {
  strings:
    $key_bd56 = { ea 24 [2] d8 06 [2] de 33 [2] f0 33 [2] cf 2f }

  condition:
    any of them
}