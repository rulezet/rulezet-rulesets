rule TTP_XOR_WriteProcessMemory_ce23 {
  strings:
    $key_ce23 = { 99 51 [2] ab 73 [2] ad 46 [2] 83 46 [2] bc 5a }

  condition:
    any of them
}