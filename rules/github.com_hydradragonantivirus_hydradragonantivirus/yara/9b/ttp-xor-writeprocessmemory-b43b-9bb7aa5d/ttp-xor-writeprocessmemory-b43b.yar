rule TTP_XOR_WriteProcessMemory_b43b {
  strings:
    $key_b43b = { e3 49 [2] d1 6b [2] d7 5e [2] f9 5e [2] c6 42 }

  condition:
    any of them
}