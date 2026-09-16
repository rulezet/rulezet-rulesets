rule TTP_XOR_WriteProcessMemory_bd34 {
  strings:
    $key_bd34 = { ea 46 [2] d8 64 [2] de 51 [2] f0 51 [2] cf 4d }

  condition:
    any of them
}