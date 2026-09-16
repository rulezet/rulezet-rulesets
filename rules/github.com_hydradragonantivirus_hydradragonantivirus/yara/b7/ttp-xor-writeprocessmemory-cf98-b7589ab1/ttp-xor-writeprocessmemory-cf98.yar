rule TTP_XOR_WriteProcessMemory_cf98 {
  strings:
    $key_cf98 = { 98 ea [2] aa c8 [2] ac fd [2] 82 fd [2] bd e1 }

  condition:
    any of them
}