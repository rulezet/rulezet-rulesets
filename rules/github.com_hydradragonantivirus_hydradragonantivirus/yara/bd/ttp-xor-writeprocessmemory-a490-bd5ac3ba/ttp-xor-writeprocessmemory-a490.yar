rule TTP_XOR_WriteProcessMemory_a490 {
  strings:
    $key_a490 = { f3 e2 [2] c1 c0 [2] c7 f5 [2] e9 f5 [2] d6 e9 }

  condition:
    any of them
}