rule TTP_XOR_WriteProcessMemory_bd1d {
  strings:
    $key_bd1d = { ea 6f [2] d8 4d [2] de 78 [2] f0 78 [2] cf 64 }

  condition:
    any of them
}