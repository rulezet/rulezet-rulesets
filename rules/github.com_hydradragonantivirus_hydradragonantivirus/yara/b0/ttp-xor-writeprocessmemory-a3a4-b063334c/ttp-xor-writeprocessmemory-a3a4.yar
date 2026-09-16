rule TTP_XOR_WriteProcessMemory_a3a4 {
  strings:
    $key_a3a4 = { f4 d6 [2] c6 f4 [2] c0 c1 [2] ee c1 [2] d1 dd }

  condition:
    any of them
}