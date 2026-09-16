rule TTP_XOR_WriteProcessMemory_b40b {
  strings:
    $key_b40b = { e3 79 [2] d1 5b [2] d7 6e [2] f9 6e [2] c6 72 }

  condition:
    any of them
}