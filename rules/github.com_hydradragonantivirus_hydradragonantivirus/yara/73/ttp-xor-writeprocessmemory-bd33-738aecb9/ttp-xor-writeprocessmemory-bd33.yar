rule TTP_XOR_WriteProcessMemory_bd33 {
  strings:
    $key_bd33 = { ea 41 [2] d8 63 [2] de 56 [2] f0 56 [2] cf 4a }

  condition:
    any of them
}