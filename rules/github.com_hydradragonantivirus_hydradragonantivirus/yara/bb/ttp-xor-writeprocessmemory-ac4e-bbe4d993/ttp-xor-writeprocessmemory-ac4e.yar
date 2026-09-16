rule TTP_XOR_WriteProcessMemory_ac4e {
  strings:
    $key_ac4e = { fb 3c [2] c9 1e [2] cf 2b [2] e1 2b [2] de 37 }

  condition:
    any of them
}