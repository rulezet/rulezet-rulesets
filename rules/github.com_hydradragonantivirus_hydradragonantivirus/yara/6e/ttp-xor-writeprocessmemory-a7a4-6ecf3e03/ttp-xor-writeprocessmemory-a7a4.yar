rule TTP_XOR_WriteProcessMemory_a7a4 {
  strings:
    $key_a7a4 = { f0 d6 [2] c2 f4 [2] c4 c1 [2] ea c1 [2] d5 dd }

  condition:
    any of them
}