rule TTP_XOR_WriteProcessMemory_a75c {
  strings:
    $key_a75c = { f0 2e [2] c2 0c [2] c4 39 [2] ea 39 [2] d5 25 }

  condition:
    any of them
}