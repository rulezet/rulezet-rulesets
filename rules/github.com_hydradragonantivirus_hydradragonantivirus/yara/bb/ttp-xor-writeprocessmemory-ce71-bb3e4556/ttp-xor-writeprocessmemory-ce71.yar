rule TTP_XOR_WriteProcessMemory_ce71 {
  strings:
    $key_ce71 = { 99 03 [2] ab 21 [2] ad 14 [2] 83 14 [2] bc 08 }

  condition:
    any of them
}