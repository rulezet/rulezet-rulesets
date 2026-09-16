rule TTP_XOR_WriteProcessMemory_ce6c {
  strings:
    $key_ce6c = { 99 1e [2] ab 3c [2] ad 09 [2] 83 09 [2] bc 15 }

  condition:
    any of them
}