rule TTP_XOR_WriteProcessMemory_ce50 {
  strings:
    $key_ce50 = { 99 22 [2] ab 00 [2] ad 35 [2] 83 35 [2] bc 29 }

  condition:
    any of them
}