rule TTP_XOR_WriteProcessMemory_ce4c {
  strings:
    $key_ce4c = { 99 3e [2] ab 1c [2] ad 29 [2] 83 29 [2] bc 35 }

  condition:
    any of them
}