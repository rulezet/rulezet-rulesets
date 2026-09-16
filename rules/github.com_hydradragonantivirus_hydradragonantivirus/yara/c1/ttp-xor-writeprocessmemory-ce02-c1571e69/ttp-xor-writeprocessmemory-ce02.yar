rule TTP_XOR_WriteProcessMemory_ce02 {
  strings:
    $key_ce02 = { 99 70 [2] ab 52 [2] ad 67 [2] 83 67 [2] bc 7b }

  condition:
    any of them
}