rule TTP_XOR_WriteProcessMemory_5b98 {
  strings:
    $key_5b98 = { 0c ea [2] 3e c8 [2] 38 fd [2] 16 fd [2] 29 e1 }

  condition:
    any of them
}