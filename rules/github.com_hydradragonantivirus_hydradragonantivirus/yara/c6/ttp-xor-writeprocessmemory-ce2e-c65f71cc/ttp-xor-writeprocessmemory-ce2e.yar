rule TTP_XOR_WriteProcessMemory_ce2e {
  strings:
    $key_ce2e = { 99 5c [2] ab 7e [2] ad 4b [2] 83 4b [2] bc 57 }

  condition:
    any of them
}