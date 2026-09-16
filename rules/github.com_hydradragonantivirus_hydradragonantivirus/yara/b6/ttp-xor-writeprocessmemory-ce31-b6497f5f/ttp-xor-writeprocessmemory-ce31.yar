rule TTP_XOR_WriteProcessMemory_ce31 {
  strings:
    $key_ce31 = { 99 43 [2] ab 61 [2] ad 54 [2] 83 54 [2] bc 48 }

  condition:
    any of them
}