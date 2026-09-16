rule TTP_XOR_WriteProcessMemory_a7a6 {
  strings:
    $key_a7a6 = { f0 d4 [2] c2 f6 [2] c4 c3 [2] ea c3 [2] d5 df }

  condition:
    any of them
}