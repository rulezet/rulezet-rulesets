rule TTP_XOR_WriteProcessMemory_a773 {
  strings:
    $key_a773 = { f0 01 [2] c2 23 [2] c4 16 [2] ea 16 [2] d5 0a }

  condition:
    any of them
}