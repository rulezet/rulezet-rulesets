rule TTP_XOR_WriteProcessMemory_5198 {
  strings:
    $key_5198 = { 06 ea [2] 34 c8 [2] 32 fd [2] 1c fd [2] 23 e1 }

  condition:
    any of them
}