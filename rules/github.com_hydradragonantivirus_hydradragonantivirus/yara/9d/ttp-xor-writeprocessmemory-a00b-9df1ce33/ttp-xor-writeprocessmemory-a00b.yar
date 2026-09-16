rule TTP_XOR_WriteProcessMemory_a00b {
  strings:
    $key_a00b = { f7 79 [2] c5 5b [2] c3 6e [2] ed 6e [2] d2 72 }

  condition:
    any of them
}