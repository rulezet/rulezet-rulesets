rule TTP_XOR_WriteProcessMemory_a617 {
  strings:
    $key_a617 = { f1 65 [2] c3 47 [2] c5 72 [2] eb 72 [2] d4 6e }

  condition:
    any of them
}