rule TTP_XOR_WriteProcessMemory_ce21 {
  strings:
    $key_ce21 = { 99 53 [2] ab 71 [2] ad 44 [2] 83 44 [2] bc 58 }

  condition:
    any of them
}