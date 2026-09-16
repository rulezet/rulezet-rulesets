rule TTP_XOR_WriteProcessMemory_0e98 {
  strings:
    $key_0e98 = { 59 ea [2] 6b c8 [2] 6d fd [2] 43 fd [2] 7c e1 }

  condition:
    any of them
}