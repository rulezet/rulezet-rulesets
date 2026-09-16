rule TTP_XOR_WriteProcessMemory_bd13 {
  strings:
    $key_bd13 = { ea 61 [2] d8 43 [2] de 76 [2] f0 76 [2] cf 6a }

  condition:
    any of them
}