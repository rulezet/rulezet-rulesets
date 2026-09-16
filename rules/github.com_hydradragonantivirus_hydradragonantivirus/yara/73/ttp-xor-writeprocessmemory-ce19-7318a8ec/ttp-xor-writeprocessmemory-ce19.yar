rule TTP_XOR_WriteProcessMemory_ce19 {
  strings:
    $key_ce19 = { 99 6b [2] ab 49 [2] ad 7c [2] 83 7c [2] bc 60 }

  condition:
    any of them
}