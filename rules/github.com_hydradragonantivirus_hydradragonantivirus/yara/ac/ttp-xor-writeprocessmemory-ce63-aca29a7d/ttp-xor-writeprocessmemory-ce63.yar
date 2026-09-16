rule TTP_XOR_WriteProcessMemory_ce63 {
  strings:
    $key_ce63 = { 99 11 [2] ab 33 [2] ad 06 [2] 83 06 [2] bc 1a }

  condition:
    any of them
}