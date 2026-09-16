rule TTP_XOR_WriteProcessMemory_a3a2 {
  strings:
    $key_a3a2 = { f4 d0 [2] c6 f2 [2] c0 c7 [2] ee c7 [2] d1 db }

  condition:
    any of them
}