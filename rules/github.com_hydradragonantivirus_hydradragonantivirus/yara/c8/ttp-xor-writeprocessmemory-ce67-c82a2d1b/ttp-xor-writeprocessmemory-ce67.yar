rule TTP_XOR_WriteProcessMemory_ce67 {
  strings:
    $key_ce67 = { 99 15 [2] ab 37 [2] ad 02 [2] 83 02 [2] bc 1e }

  condition:
    any of them
}