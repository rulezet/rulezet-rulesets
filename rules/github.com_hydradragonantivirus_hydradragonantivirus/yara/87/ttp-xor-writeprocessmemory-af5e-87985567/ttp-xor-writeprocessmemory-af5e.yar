rule TTP_XOR_WriteProcessMemory_af5e {
  strings:
    $key_af5e = { f8 2c [2] ca 0e [2] cc 3b [2] e2 3b [2] dd 27 }

  condition:
    any of them
}