rule TTP_XOR_WriteProcessMemory_a7e2 {
  strings:
    $key_a7e2 = { f0 90 [2] c2 b2 [2] c4 87 [2] ea 87 [2] d5 9b }

  condition:
    any of them
}