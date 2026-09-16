rule TTP_XOR_WriteProcessMemory_bd4e {
  strings:
    $key_bd4e = { ea 3c [2] d8 1e [2] de 2b [2] f0 2b [2] cf 37 }

  condition:
    any of them
}