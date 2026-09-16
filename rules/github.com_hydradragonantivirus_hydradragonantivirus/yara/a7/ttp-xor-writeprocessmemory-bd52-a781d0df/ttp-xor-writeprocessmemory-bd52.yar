rule TTP_XOR_WriteProcessMemory_bd52 {
  strings:
    $key_bd52 = { ea 20 [2] d8 02 [2] de 37 [2] f0 37 [2] cf 2b }

  condition:
    any of them
}