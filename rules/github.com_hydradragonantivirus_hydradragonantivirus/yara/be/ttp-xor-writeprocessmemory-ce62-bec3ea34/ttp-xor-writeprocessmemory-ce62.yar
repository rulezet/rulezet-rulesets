rule TTP_XOR_WriteProcessMemory_ce62 {
  strings:
    $key_ce62 = { 99 10 [2] ab 32 [2] ad 07 [2] 83 07 [2] bc 1b }

  condition:
    any of them
}