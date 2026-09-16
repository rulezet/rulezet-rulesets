rule TTP_XOR_WriteProcessMemory_ce4b {
  strings:
    $key_ce4b = { 99 39 [2] ab 1b [2] ad 2e [2] 83 2e [2] bc 32 }

  condition:
    any of them
}