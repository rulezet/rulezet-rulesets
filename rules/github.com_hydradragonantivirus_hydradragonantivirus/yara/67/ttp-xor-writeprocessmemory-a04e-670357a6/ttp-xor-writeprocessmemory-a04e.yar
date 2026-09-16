rule TTP_XOR_WriteProcessMemory_a04e {
  strings:
    $key_a04e = { f7 3c [2] c5 1e [2] c3 2b [2] ed 2b [2] d2 37 }

  condition:
    any of them
}