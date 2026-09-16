rule TTP_XOR_WriteProcessMemory_a681 {
  strings:
    $key_a681 = { f1 f3 [2] c3 d1 [2] c5 e4 [2] eb e4 [2] d4 f8 }

  condition:
    any of them
}