rule TTP_XOR_WriteProcessMemory_a413 {
  strings:
    $key_a413 = { f3 61 [2] c1 43 [2] c7 76 [2] e9 76 [2] d6 6a }

  condition:
    any of them
}