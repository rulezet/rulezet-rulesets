rule TTP_XOR_WriteProcessMemory_0b98 {
  strings:
    $key_0b98 = { 5c ea [2] 6e c8 [2] 68 fd [2] 46 fd [2] 79 e1 }

  condition:
    any of them
}