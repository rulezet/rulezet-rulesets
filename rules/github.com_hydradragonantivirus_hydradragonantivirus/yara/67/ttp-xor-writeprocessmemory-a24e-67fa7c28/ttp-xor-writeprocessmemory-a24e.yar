rule TTP_XOR_WriteProcessMemory_a24e {
  strings:
    $key_a24e = { f5 3c [2] c7 1e [2] c1 2b [2] ef 2b [2] d0 37 }

  condition:
    any of them
}