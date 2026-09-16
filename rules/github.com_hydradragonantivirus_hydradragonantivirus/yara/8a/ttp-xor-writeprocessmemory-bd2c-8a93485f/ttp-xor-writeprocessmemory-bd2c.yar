rule TTP_XOR_WriteProcessMemory_bd2c {
  strings:
    $key_bd2c = { ea 5e [2] d8 7c [2] de 49 [2] f0 49 [2] cf 55 }

  condition:
    any of them
}