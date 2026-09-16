rule TTP_XOR_WriteProcessMemory_ce59 {
  strings:
    $key_ce59 = { 99 2b [2] ab 09 [2] ad 3c [2] 83 3c [2] bc 20 }

  condition:
    any of them
}