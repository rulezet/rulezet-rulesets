rule TTP_XOR_WriteProcessMemory_a64b {
  strings:
    $key_a64b = { f1 39 [2] c3 1b [2] c5 2e [2] eb 2e [2] d4 32 }

  condition:
    any of them
}