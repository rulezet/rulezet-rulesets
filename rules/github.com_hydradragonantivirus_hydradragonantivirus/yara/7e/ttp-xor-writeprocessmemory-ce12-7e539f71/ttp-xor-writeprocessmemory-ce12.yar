rule TTP_XOR_WriteProcessMemory_ce12 {
  strings:
    $key_ce12 = { 99 60 [2] ab 42 [2] ad 77 [2] 83 77 [2] bc 6b }

  condition:
    any of them
}