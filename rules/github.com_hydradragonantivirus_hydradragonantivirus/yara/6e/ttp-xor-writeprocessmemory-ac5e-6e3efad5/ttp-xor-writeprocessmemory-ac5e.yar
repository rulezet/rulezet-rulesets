rule TTP_XOR_WriteProcessMemory_ac5e {
  strings:
    $key_ac5e = { fb 2c [2] c9 0e [2] cf 3b [2] e1 3b [2] de 27 }

  condition:
    any of them
}