rule TTP_XOR_WriteProcessMemory_a0a0 {
  strings:
    $key_a0a0 = { f7 d2 [2] c5 f0 [2] c3 c5 [2] ed c5 [2] d2 d9 }

  condition:
    any of them
}