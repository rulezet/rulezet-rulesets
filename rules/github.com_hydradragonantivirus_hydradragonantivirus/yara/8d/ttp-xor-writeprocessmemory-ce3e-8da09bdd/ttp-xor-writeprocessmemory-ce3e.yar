rule TTP_XOR_WriteProcessMemory_ce3e {
  strings:
    $key_ce3e = { 99 4c [2] ab 6e [2] ad 5b [2] 83 5b [2] bc 47 }

  condition:
    any of them
}