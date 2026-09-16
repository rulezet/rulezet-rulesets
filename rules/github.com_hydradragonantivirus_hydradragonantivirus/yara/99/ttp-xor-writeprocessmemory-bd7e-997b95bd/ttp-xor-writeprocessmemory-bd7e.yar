rule TTP_XOR_WriteProcessMemory_bd7e {
  strings:
    $key_bd7e = { ea 0c [2] d8 2e [2] de 1b [2] f0 1b [2] cf 07 }

  condition:
    any of them
}