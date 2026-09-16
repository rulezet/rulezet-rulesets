rule TTP_XOR_WriteProcessMemory_a50b {
  strings:
    $key_a50b = { f2 79 [2] c0 5b [2] c6 6e [2] e8 6e [2] d7 72 }

  condition:
    any of them
}