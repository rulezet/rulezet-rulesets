rule TTP_XOR_WriteProcessMemory_5a98 {
  strings:
    $key_5a98 = { 0d ea [2] 3f c8 [2] 39 fd [2] 17 fd [2] 28 e1 }

  condition:
    any of them
}