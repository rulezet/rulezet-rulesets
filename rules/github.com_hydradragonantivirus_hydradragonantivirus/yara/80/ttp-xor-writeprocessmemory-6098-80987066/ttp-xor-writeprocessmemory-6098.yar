rule TTP_XOR_WriteProcessMemory_6098 {
  strings:
    $key_6098 = { 37 ea [2] 05 c8 [2] 03 fd [2] 2d fd [2] 12 e1 }

  condition:
    any of them
}