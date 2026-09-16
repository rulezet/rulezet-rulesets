rule TTP_XOR_WriteProcessMemory_6360 {
  strings:
    $key_6360 = { 34 12 [2] 06 30 [2] 00 05 [2] 2e 05 [2] 11 19 }

  condition:
    any of them
}