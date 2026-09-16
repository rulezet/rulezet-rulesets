rule TTP_XOR_WriteProcessMemory_a55b {
  strings:
    $key_a55b = { f2 29 [2] c0 0b [2] c6 3e [2] e8 3e [2] d7 22 }

  condition:
    any of them
}