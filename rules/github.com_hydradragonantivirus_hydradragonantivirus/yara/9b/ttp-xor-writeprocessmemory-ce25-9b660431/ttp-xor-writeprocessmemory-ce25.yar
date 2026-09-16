rule TTP_XOR_WriteProcessMemory_ce25 {
  strings:
    $key_ce25 = { 99 57 [2] ab 75 [2] ad 40 [2] 83 40 [2] bc 5c }

  condition:
    any of them
}