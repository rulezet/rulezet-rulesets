rule TTP_XOR_WriteProcessMemory_bd3e {
  strings:
    $key_bd3e = { ea 4c [2] d8 6e [2] de 5b [2] f0 5b [2] cf 47 }

  condition:
    any of them
}