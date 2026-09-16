rule TTP_XOR_WriteProcessMemory_5f98 {
  strings:
    $key_5f98 = { 08 ea [2] 3a c8 [2] 3c fd [2] 12 fd [2] 2d e1 }

  condition:
    any of them
}