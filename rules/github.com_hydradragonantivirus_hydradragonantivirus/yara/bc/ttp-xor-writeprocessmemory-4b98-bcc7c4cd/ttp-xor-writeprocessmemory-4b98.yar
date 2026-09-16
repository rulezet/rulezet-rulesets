rule TTP_XOR_WriteProcessMemory_4b98 {
  strings:
    $key_4b98 = { 1c ea [2] 2e c8 [2] 28 fd [2] 06 fd [2] 39 e1 }

  condition:
    any of them
}