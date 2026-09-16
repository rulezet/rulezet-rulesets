rule TTP_XOR_WriteProcessMemory_dd98 {
  strings:
    $key_dd98 = { 8a ea [2] b8 c8 [2] be fd [2] 90 fd [2] af e1 }

  condition:
    any of them
}