rule TTP_XOR_WriteProcessMemory_bd51 {
  strings:
    $key_bd51 = { ea 23 [2] d8 01 [2] de 34 [2] f0 34 [2] cf 28 }

  condition:
    any of them
}