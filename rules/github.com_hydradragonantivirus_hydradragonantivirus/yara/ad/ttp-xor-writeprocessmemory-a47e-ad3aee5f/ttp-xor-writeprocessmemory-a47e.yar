rule TTP_XOR_WriteProcessMemory_a47e {
  strings:
    $key_a47e = { f3 0c [2] c1 2e [2] c7 1b [2] e9 1b [2] d6 07 }

  condition:
    any of them
}