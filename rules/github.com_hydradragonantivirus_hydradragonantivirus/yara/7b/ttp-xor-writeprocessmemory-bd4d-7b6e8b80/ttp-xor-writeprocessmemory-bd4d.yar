rule TTP_XOR_WriteProcessMemory_bd4d {
  strings:
    $key_bd4d = { ea 3f [2] d8 1d [2] de 28 [2] f0 28 [2] cf 34 }

  condition:
    any of them
}