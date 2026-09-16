rule TTP_XOR_WriteProcessMemory_ce74 {
  strings:
    $key_ce74 = { 99 06 [2] ab 24 [2] ad 11 [2] 83 11 [2] bc 0d }

  condition:
    any of them
}