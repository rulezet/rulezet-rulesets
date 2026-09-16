rule TTP_XOR_WriteProcessMemory_a77b {
  strings:
    $key_a77b = { f0 09 [2] c2 2b [2] c4 1e [2] ea 1e [2] d5 02 }

  condition:
    any of them
}