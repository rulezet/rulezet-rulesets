rule TTP_XOR_WriteProcessMemory_a610 {
  strings:
    $key_a610 = { f1 62 [2] c3 40 [2] c5 75 [2] eb 75 [2] d4 69 }

  condition:
    any of them
}