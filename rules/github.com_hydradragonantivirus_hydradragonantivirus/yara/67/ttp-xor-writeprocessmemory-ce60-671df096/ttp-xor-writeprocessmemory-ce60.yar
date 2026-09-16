rule TTP_XOR_WriteProcessMemory_ce60 {
  strings:
    $key_ce60 = { 99 12 [2] ab 30 [2] ad 05 [2] 83 05 [2] bc 19 }

  condition:
    any of them
}