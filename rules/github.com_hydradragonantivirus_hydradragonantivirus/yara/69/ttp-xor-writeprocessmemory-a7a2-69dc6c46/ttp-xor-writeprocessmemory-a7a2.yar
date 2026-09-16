rule TTP_XOR_WriteProcessMemory_a7a2 {
  strings:
    $key_a7a2 = { f0 d0 [2] c2 f2 [2] c4 c7 [2] ea c7 [2] d5 db }

  condition:
    any of them
}