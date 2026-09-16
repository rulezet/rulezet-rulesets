rule TTP_XOR_WriteProcessMemory_a081 {
  strings:
    $key_a081 = { f7 f3 [2] c5 d1 [2] c3 e4 [2] ed e4 [2] d2 f8 }

  condition:
    any of them
}