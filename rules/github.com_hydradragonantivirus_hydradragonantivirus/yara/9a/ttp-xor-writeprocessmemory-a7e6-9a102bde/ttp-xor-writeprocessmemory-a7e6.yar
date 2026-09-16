rule TTP_XOR_WriteProcessMemory_a7e6 {
  strings:
    $key_a7e6 = { f0 94 [2] c2 b6 [2] c4 83 [2] ea 83 [2] d5 9f }

  condition:
    any of them
}