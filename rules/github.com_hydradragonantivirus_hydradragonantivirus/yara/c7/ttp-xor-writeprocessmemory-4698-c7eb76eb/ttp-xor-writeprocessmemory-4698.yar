rule TTP_XOR_WriteProcessMemory_4698 {
  strings:
    $key_4698 = { 11 ea [2] 23 c8 [2] 25 fd [2] 0b fd [2] 34 e1 }

  condition:
    any of them
}