rule TTP_XOR_WriteProcessMemory_ce65 {
  strings:
    $key_ce65 = { 99 17 [2] ab 35 [2] ad 00 [2] 83 00 [2] bc 1c }

  condition:
    any of them
}