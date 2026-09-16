rule TTP_XOR_WriteProcessMemory_ce6b {
  strings:
    $key_ce6b = { 99 19 [2] ab 3b [2] ad 0e [2] 83 0e [2] bc 12 }

  condition:
    any of them
}