rule TTP_XOR_WriteProcessMemory_a73e {
  strings:
    $key_a73e = { f0 4c [2] c2 6e [2] c4 5b [2] ea 5b [2] d5 47 }

  condition:
    any of them
}