rule TTP_XOR_WriteProcessMemory_b54b {
  strings:
    $key_b54b = { e2 39 [2] d0 1b [2] d6 2e [2] f8 2e [2] c7 32 }

  condition:
    any of them
}