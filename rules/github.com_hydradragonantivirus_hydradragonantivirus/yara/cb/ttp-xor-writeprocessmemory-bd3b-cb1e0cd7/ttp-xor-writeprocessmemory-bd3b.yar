rule TTP_XOR_WriteProcessMemory_bd3b {
  strings:
    $key_bd3b = { ea 49 [2] d8 6b [2] de 5e [2] f0 5e [2] cf 42 }

  condition:
    any of them
}