rule TTP_XOR_WriteProcessMemory_6298 {
  strings:
    $key_6298 = { 35 ea [2] 07 c8 [2] 01 fd [2] 2f fd [2] 10 e1 }

  condition:
    any of them
}