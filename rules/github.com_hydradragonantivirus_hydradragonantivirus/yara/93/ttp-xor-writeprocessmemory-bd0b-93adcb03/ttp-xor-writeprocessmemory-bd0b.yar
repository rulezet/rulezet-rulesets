rule TTP_XOR_WriteProcessMemory_bd0b {
  strings:
    $key_bd0b = { ea 79 [2] d8 5b [2] de 6e [2] f0 6e [2] cf 72 }

  condition:
    any of them
}