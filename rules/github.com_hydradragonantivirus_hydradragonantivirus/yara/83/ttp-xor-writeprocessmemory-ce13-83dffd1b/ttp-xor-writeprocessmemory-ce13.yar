rule TTP_XOR_WriteProcessMemory_ce13 {
  strings:
    $key_ce13 = { 99 61 [2] ab 43 [2] ad 76 [2] 83 76 [2] bc 6a }

  condition:
    any of them
}