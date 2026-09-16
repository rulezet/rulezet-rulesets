rule TTP_XOR_WriteProcessMemory_b56b {
  strings:
    $key_b56b = { e2 19 [2] d0 3b [2] d6 0e [2] f8 0e [2] c7 12 }

  condition:
    any of them
}