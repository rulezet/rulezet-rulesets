rule TTP_XOR_WriteProcessMemory_3b98 {
  strings:
    $key_3b98 = { 6c ea [2] 5e c8 [2] 58 fd [2] 76 fd [2] 49 e1 }

  condition:
    any of them
}