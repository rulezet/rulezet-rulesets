rule TTP_XOR_WriteProcessMemory_a762 {
  strings:
    $key_a762 = { f0 10 [2] c2 32 [2] c4 07 [2] ea 07 [2] d5 1b }

  condition:
    any of them
}