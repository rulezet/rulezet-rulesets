rule TTP_XOR_WriteProcessMemory_a67e {
  strings:
    $key_a67e = { f1 0c [2] c3 2e [2] c5 1b [2] eb 1b [2] d4 07 }

  condition:
    any of them
}