rule TTP_XOR_WriteProcessMemory_bd46 {
  strings:
    $key_bd46 = { ea 34 [2] d8 16 [2] de 23 [2] f0 23 [2] cf 3f }

  condition:
    any of them
}