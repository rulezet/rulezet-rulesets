rule TTP_XOR_WriteProcessMemory_a690 {
  strings:
    $key_a690 = { f1 e2 [2] c3 c0 [2] c5 f5 [2] eb f5 [2] d4 e9 }

  condition:
    any of them
}