rule TTP_XOR_WriteProcessMemory_a69c {
  strings:
    $key_a69c = { f1 ee [2] c3 cc [2] c5 f9 [2] eb f9 [2] d4 e5 }

  condition:
    any of them
}