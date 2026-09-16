rule TTP_XOR_WriteProcessMemory_a7f3 {
  strings:
    $key_a7f3 = { f0 81 [2] c2 a3 [2] c4 96 [2] ea 96 [2] d5 8a }

  condition:
    any of them
}