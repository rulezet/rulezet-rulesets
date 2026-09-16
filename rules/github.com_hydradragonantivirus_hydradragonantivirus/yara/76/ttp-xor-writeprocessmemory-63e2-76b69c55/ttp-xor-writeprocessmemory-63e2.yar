rule TTP_XOR_WriteProcessMemory_63e2 {
  strings:
    $key_63e2 = { 34 90 [2] 06 b2 [2] 00 87 [2] 2e 87 [2] 11 9b }

  condition:
    any of them
}