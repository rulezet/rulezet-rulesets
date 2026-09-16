rule TTP_XOR_WriteProcessMemory_bd5d {
  strings:
    $key_bd5d = { ea 2f [2] d8 0d [2] de 38 [2] f0 38 [2] cf 24 }

  condition:
    any of them
}