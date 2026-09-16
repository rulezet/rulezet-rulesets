rule TTP_XOR_WriteProcessMemory_4498 {
  strings:
    $key_4498 = { 13 ea [2] 21 c8 [2] 27 fd [2] 09 fd [2] 36 e1 }

  condition:
    any of them
}