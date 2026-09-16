rule TTP_XOR_WriteProcessMemory_ce00 {
  strings:
    $key_ce00 = { 99 72 [2] ab 50 [2] ad 65 [2] 83 65 [2] bc 79 }

  condition:
    any of them
}