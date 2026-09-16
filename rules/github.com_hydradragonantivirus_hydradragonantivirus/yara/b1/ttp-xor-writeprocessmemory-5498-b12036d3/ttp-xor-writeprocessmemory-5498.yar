rule TTP_XOR_WriteProcessMemory_5498 {
  strings:
    $key_5498 = { 03 ea [2] 31 c8 [2] 37 fd [2] 19 fd [2] 26 e1 }

  condition:
    any of them
}