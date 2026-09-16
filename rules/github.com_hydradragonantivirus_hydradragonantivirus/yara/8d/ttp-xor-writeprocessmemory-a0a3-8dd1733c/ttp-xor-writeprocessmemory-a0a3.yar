rule TTP_XOR_WriteProcessMemory_a0a3 {
  strings:
    $key_a0a3 = { f7 d1 [2] c5 f3 [2] c3 c6 [2] ed c6 [2] d2 da }

  condition:
    any of them
}