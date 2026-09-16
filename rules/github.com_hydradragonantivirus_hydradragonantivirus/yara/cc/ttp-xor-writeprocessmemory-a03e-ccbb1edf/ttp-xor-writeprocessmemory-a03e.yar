rule TTP_XOR_WriteProcessMemory_a03e {
  strings:
    $key_a03e = { f7 4c [2] c5 6e [2] c3 5b [2] ed 5b [2] d2 47 }

  condition:
    any of them
}