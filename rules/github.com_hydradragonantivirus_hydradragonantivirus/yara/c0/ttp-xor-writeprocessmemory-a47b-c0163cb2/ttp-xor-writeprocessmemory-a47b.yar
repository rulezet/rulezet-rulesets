rule TTP_XOR_WriteProcessMemory_a47b {
  strings:
    $key_a47b = { f3 09 [2] c1 2b [2] c7 1e [2] e9 1e [2] d6 02 }

  condition:
    any of them
}