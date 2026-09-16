rule TTP_XOR_WriteProcessMemory_4a98 {
  strings:
    $key_4a98 = { 1d ea [2] 2f c8 [2] 29 fd [2] 07 fd [2] 38 e1 }

  condition:
    any of them
}