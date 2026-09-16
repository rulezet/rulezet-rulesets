rule TTP_XOR_WriteProcessMemory_ce5e {
  strings:
    $key_ce5e = { 99 2c [2] ab 0e [2] ad 3b [2] 83 3b [2] bc 27 }

  condition:
    any of them
}