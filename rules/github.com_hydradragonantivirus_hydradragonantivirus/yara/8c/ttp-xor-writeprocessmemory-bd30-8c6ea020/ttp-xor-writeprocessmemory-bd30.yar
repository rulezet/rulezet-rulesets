rule TTP_XOR_WriteProcessMemory_bd30 {
  strings:
    $key_bd30 = { ea 42 [2] d8 60 [2] de 55 [2] f0 55 [2] cf 49 }

  condition:
    any of them
}