rule TTP_XOR_WriteProcessMemory_a5b0 {
  strings:
    $key_a5b0 = { f2 c2 [2] c0 e0 [2] c6 d5 [2] e8 d5 [2] d7 c9 }

  condition:
    any of them
}