rule TTP_XOR_WriteProcessMemory_a746 {
  strings:
    $key_a746 = { f0 34 [2] c2 16 [2] c4 23 [2] ea 23 [2] d5 3f }

  condition:
    any of them
}