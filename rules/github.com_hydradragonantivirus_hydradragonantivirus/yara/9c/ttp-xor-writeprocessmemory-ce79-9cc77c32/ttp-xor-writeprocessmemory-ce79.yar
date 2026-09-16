rule TTP_XOR_WriteProcessMemory_ce79 {
  strings:
    $key_ce79 = { 99 0b [2] ab 29 [2] ad 1c [2] 83 1c [2] bc 00 }

  condition:
    any of them
}