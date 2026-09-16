rule TTP_XOR_WriteProcessMemory_a44e {
  strings:
    $key_a44e = { f3 3c [2] c1 1e [2] c7 2b [2] e9 2b [2] d6 37 }

  condition:
    any of them
}