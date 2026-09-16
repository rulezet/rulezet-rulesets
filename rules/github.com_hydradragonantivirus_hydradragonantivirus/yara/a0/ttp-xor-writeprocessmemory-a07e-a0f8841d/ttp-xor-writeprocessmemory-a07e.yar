rule TTP_XOR_WriteProcessMemory_a07e {
  strings:
    $key_a07e = { f7 0c [2] c5 2e [2] c3 1b [2] ed 1b [2] d2 07 }

  condition:
    any of them
}