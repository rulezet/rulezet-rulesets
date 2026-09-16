rule TTP_XOR_WriteProcessMemory_a3a5 {
  strings:
    $key_a3a5 = { f4 d7 [2] c6 f5 [2] c0 c0 [2] ee c0 [2] d1 dc }

  condition:
    any of them
}