rule TTP_XOR_WriteProcessMemory_0f98 {
  strings:
    $key_0f98 = { 58 ea [2] 6a c8 [2] 6c fd [2] 42 fd [2] 7d e1 }

  condition:
    any of them
}