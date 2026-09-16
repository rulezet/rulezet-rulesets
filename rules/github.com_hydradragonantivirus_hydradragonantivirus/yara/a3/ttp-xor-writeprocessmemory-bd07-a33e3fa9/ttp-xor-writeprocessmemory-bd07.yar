rule TTP_XOR_WriteProcessMemory_bd07 {
  strings:
    $key_bd07 = { ea 75 [2] d8 57 [2] de 62 [2] f0 62 [2] cf 7e }

  condition:
    any of them
}