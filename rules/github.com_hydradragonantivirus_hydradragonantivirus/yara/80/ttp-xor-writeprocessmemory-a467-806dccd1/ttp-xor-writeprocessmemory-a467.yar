rule TTP_XOR_WriteProcessMemory_a467 {
  strings:
    $key_a467 = { f3 15 [2] c1 37 [2] c7 02 [2] e9 02 [2] d6 1e }

  condition:
    any of them
}