rule TTP_XOR_WriteProcessMemory_a73b {
  strings:
    $key_a73b = { f0 49 [2] c2 6b [2] c4 5e [2] ea 5e [2] d5 42 }

  condition:
    any of them
}