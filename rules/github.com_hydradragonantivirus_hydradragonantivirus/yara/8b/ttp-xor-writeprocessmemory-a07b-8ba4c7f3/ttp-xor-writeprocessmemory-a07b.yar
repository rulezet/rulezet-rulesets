rule TTP_XOR_WriteProcessMemory_a07b {
  strings:
    $key_a07b = { f7 09 [2] c5 2b [2] c3 1e [2] ed 1e [2] d2 02 }

  condition:
    any of them
}