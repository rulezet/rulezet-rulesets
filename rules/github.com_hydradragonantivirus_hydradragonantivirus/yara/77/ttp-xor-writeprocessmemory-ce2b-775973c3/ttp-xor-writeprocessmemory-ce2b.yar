rule TTP_XOR_WriteProcessMemory_ce2b {
  strings:
    $key_ce2b = { 99 59 [2] ab 7b [2] ad 4e [2] 83 4e [2] bc 52 }

  condition:
    any of them
}