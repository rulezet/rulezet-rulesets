rule TTP_XOR_WriteProcessMemory_a55e {
  strings:
    $key_a55e = { f2 2c [2] c0 0e [2] c6 3b [2] e8 3b [2] d7 27 }

  condition:
    any of them
}