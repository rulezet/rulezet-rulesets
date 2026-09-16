rule TTP_XOR_WriteProcessMemory_a745 {
  strings:
    $key_a745 = { f0 37 [2] c2 15 [2] c4 20 [2] ea 20 [2] d5 3c }

  condition:
    any of them
}