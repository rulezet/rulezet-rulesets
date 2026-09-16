rule TTP_XOR_WriteProcessMemory_bd7b {
  strings:
    $key_bd7b = { ea 09 [2] d8 2b [2] de 1e [2] f0 1e [2] cf 02 }

  condition:
    any of them
}