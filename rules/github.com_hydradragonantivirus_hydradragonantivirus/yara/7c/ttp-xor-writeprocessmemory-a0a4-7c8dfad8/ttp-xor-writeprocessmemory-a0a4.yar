rule TTP_XOR_WriteProcessMemory_a0a4 {
  strings:
    $key_a0a4 = { f7 d6 [2] c5 f4 [2] c3 c1 [2] ed c1 [2] d2 dd }

  condition:
    any of them
}