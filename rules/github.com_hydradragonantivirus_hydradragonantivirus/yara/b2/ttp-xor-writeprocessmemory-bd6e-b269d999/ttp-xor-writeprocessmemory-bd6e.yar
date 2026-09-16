rule TTP_XOR_WriteProcessMemory_bd6e {
  strings:
    $key_bd6e = { ea 1c [2] d8 3e [2] de 0b [2] f0 0b [2] cf 17 }

  condition:
    any of them
}