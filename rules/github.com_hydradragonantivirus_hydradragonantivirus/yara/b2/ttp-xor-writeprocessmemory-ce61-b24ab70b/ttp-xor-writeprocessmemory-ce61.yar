rule TTP_XOR_WriteProcessMemory_ce61 {
  strings:
    $key_ce61 = { 99 13 [2] ab 31 [2] ad 04 [2] 83 04 [2] bc 18 }

  condition:
    any of them
}