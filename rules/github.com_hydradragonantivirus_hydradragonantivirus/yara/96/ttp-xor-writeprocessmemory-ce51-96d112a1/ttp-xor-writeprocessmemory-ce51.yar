rule TTP_XOR_WriteProcessMemory_ce51 {
  strings:
    $key_ce51 = { 99 23 [2] ab 01 [2] ad 34 [2] 83 34 [2] bc 28 }

  condition:
    any of them
}