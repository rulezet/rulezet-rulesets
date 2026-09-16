rule TTP_XOR_WriteProcessMemory_bd48 {
  strings:
    $key_bd48 = { ea 3a [2] d8 18 [2] de 2d [2] f0 2d [2] cf 31 }

  condition:
    any of them
}