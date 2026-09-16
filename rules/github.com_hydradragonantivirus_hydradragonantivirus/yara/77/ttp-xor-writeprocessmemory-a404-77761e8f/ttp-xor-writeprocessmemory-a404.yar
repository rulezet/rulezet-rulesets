rule TTP_XOR_WriteProcessMemory_a404 {
  strings:
    $key_a404 = { f3 76 [2] c1 54 [2] c7 61 [2] e9 61 [2] d6 7d }

  condition:
    any of them
}