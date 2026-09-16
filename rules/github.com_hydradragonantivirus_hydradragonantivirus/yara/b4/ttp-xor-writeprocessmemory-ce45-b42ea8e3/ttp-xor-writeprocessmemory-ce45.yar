rule TTP_XOR_WriteProcessMemory_ce45 {
  strings:
    $key_ce45 = { 99 37 [2] ab 15 [2] ad 20 [2] 83 20 [2] bc 3c }

  condition:
    any of them
}