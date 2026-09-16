rule TTP_XOR_WriteProcessMemory_7a98 {
  strings:
    $key_7a98 = { 2d ea [2] 1f c8 [2] 19 fd [2] 37 fd [2] 08 e1 }

  condition:
    any of them
}