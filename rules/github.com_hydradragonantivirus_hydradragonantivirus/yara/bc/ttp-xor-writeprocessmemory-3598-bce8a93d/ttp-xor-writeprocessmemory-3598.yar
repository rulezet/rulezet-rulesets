rule TTP_XOR_WriteProcessMemory_3598 {
  strings:
    $key_3598 = { 62 ea [2] 50 c8 [2] 56 fd [2] 78 fd [2] 47 e1 }

  condition:
    any of them
}