rule TTP_XOR_WriteProcessMemory_ce55 {
  strings:
    $key_ce55 = { 99 27 [2] ab 05 [2] ad 30 [2] 83 30 [2] bc 2c }

  condition:
    any of them
}