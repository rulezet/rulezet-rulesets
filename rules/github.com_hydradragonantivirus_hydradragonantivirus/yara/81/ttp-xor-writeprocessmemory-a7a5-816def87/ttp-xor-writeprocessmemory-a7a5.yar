rule TTP_XOR_WriteProcessMemory_a7a5 {
  strings:
    $key_a7a5 = { f0 d7 [2] c2 f5 [2] c4 c0 [2] ea c0 [2] d5 dc }

  condition:
    any of them
}