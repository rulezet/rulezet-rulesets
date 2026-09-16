rule TTP_XOR_WriteProcessMemory_bd0d {
  strings:
    $key_bd0d = { ea 7f [2] d8 5d [2] de 68 [2] f0 68 [2] cf 74 }

  condition:
    any of them
}