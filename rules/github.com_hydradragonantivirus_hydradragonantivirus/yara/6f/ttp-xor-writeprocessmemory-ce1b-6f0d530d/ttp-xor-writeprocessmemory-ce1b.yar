rule TTP_XOR_WriteProcessMemory_ce1b {
  strings:
    $key_ce1b = { 99 69 [2] ab 4b [2] ad 7e [2] 83 7e [2] bc 62 }

  condition:
    any of them
}