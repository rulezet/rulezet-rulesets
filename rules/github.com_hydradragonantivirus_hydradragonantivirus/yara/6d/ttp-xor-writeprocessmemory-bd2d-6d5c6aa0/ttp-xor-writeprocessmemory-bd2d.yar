rule TTP_XOR_WriteProcessMemory_bd2d {
  strings:
    $key_bd2d = { ea 5f [2] d8 7d [2] de 48 [2] f0 48 [2] cf 54 }

  condition:
    any of them
}