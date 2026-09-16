rule TTP_XOR_WriteProcessMemory_a64e {
  strings:
    $key_a64e = { f1 3c [2] c3 1e [2] c5 2b [2] eb 2b [2] d4 37 }

  condition:
    any of them
}