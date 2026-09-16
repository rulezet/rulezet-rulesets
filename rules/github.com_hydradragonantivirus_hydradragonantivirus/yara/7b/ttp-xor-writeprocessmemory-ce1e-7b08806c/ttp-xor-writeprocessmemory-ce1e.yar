rule TTP_XOR_WriteProcessMemory_ce1e {
  strings:
    $key_ce1e = { 99 6c [2] ab 4e [2] ad 7b [2] 83 7b [2] bc 67 }

  condition:
    any of them
}