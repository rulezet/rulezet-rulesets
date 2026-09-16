rule TTP_XOR_WriteProcessMemory_a767 {
  strings:
    $key_a767 = { f0 15 [2] c2 37 [2] c4 02 [2] ea 02 [2] d5 1e }

  condition:
    any of them
}