rule TTP_XOR_WriteProcessMemory_a20b {
  strings:
    $key_a20b = { f5 79 [2] c7 5b [2] c1 6e [2] ef 6e [2] d0 72 }

  condition:
    any of them
}