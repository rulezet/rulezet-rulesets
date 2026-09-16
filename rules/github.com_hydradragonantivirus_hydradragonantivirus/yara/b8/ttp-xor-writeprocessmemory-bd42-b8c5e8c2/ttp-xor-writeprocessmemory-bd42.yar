rule TTP_XOR_WriteProcessMemory_bd42 {
  strings:
    $key_bd42 = { ea 30 [2] d8 12 [2] de 27 [2] f0 27 [2] cf 3b }

  condition:
    any of them
}