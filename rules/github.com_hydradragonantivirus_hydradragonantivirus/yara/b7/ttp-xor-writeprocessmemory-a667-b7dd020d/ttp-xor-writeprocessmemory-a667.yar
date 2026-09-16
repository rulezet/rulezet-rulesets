rule TTP_XOR_WriteProcessMemory_a667 {
  strings:
    $key_a667 = { f1 15 [2] c3 37 [2] c5 02 [2] eb 02 [2] d4 1e }

  condition:
    any of them
}