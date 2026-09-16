rule TTP_XOR_WriteProcessMemory_a60b {
  strings:
    $key_a60b = { f1 79 [2] c3 5b [2] c5 6e [2] eb 6e [2] d4 72 }

  condition:
    any of them
}