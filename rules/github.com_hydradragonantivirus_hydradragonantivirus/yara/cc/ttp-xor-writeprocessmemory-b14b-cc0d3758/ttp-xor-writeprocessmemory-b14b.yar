rule TTP_XOR_WriteProcessMemory_b14b {
  strings:
    $key_b14b = { e6 39 [2] d4 1b [2] d2 2e [2] fc 2e [2] c3 32 }

  condition:
    any of them
}