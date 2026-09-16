rule TTP_XOR_WriteProcessMemory_bd45 {
  strings:
    $key_bd45 = { ea 37 [2] d8 15 [2] de 20 [2] f0 20 [2] cf 3c }

  condition:
    any of them
}