rule TTP_XOR_WriteProcessMemory_a53b {
  strings:
    $key_a53b = { f2 49 [2] c0 6b [2] c6 5e [2] e8 5e [2] d7 42 }

  condition:
    any of them
}