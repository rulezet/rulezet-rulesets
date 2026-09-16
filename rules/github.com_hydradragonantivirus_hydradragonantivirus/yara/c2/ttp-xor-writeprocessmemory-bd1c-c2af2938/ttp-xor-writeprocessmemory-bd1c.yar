rule TTP_XOR_WriteProcessMemory_bd1c {
  strings:
    $key_bd1c = { ea 6e [2] d8 4c [2] de 79 [2] f0 79 [2] cf 65 }

  condition:
    any of them
}