rule TTP_XOR_WriteProcessMemory_a5a0 {
  strings:
    $key_a5a0 = { f2 d2 [2] c0 f0 [2] c6 c5 [2] e8 c5 [2] d7 d9 }

  condition:
    any of them
}