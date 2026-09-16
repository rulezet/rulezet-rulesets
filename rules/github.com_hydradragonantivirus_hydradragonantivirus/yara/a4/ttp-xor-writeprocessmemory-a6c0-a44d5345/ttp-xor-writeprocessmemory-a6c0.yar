rule TTP_XOR_WriteProcessMemory_a6c0 {
  strings:
    $key_a6c0 = { f1 b2 [2] c3 90 [2] c5 a5 [2] eb a5 [2] d4 b9 }

  condition:
    any of them
}