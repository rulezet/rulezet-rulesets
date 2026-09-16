rule TTP_XOR_WriteProcessMemory_aa4e {
  strings:
    $key_aa4e = { fd 3c [2] cf 1e [2] c9 2b [2] e7 2b [2] d8 37 }

  condition:
    any of them
}