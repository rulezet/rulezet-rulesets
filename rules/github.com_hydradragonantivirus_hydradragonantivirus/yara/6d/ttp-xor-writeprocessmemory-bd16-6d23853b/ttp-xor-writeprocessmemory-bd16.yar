rule TTP_XOR_WriteProcessMemory_bd16 {
  strings:
    $key_bd16 = { ea 64 [2] d8 46 [2] de 73 [2] f0 73 [2] cf 6f }

  condition:
    any of them
}