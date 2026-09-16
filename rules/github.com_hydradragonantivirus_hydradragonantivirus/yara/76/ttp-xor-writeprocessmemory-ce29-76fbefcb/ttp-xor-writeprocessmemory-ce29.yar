rule TTP_XOR_WriteProcessMemory_ce29 {
  strings:
    $key_ce29 = { 99 5b [2] ab 79 [2] ad 4c [2] 83 4c [2] bc 50 }

  condition:
    any of them
}