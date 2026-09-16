rule TTP_XOR_WriteProcessMemory_a7f6 {
  strings:
    $key_a7f6 = { f0 84 [2] c2 a6 [2] c4 93 [2] ea 93 [2] d5 8f }

  condition:
    any of them
}