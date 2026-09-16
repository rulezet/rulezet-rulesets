rule TTP_XOR_WriteProcessMemory_63b2 {
  strings:
    $key_63b2 = { 34 c0 [2] 06 e2 [2] 00 d7 [2] 2e d7 [2] 11 cb }

  condition:
    any of them
}