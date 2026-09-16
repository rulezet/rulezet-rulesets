rule TTP_XOR_WriteProcessMemory_ce5c {
  strings:
    $key_ce5c = { 99 2e [2] ab 0c [2] ad 39 [2] 83 39 [2] bc 25 }

  condition:
    any of them
}