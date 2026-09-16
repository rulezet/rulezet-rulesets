rule TTP_XOR_WriteProcessMemory_a657 {
  strings:
    $key_a657 = { f1 25 [2] c3 07 [2] c5 32 [2] eb 32 [2] d4 2e }

  condition:
    any of them
}