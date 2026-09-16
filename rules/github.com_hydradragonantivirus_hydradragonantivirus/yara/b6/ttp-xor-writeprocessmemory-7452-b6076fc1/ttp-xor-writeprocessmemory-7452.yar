rule TTP_XOR_WriteProcessMemory_7452 {
  strings:
    $key_7452 = { 23 20 [2] 11 02 [2] 17 37 [2] 39 37 [2] 06 2b }

  condition:
    any of them
}