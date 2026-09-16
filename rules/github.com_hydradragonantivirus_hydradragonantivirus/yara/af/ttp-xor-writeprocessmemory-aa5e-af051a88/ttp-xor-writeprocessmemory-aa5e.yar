rule TTP_XOR_WriteProcessMemory_aa5e {
  strings:
    $key_aa5e = { fd 2c [2] cf 0e [2] c9 3b [2] e7 3b [2] d8 27 }

  condition:
    any of them
}