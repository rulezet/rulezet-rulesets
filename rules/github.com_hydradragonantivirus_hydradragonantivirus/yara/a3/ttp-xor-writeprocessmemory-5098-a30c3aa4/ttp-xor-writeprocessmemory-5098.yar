rule TTP_XOR_WriteProcessMemory_5098 {
  strings:
    $key_5098 = { 07 ea [2] 35 c8 [2] 33 fd [2] 1d fd [2] 22 e1 }

  condition:
    any of them
}