rule TTP_XOR_WriteProcessMemory_a7a7 {
  strings:
    $key_a7a7 = { f0 d5 [2] c2 f7 [2] c4 c2 [2] ea c2 [2] d5 de }

  condition:
    any of them
}