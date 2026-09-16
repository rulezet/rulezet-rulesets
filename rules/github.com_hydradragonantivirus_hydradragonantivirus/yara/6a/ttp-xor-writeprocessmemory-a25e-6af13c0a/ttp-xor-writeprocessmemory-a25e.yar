rule TTP_XOR_WriteProcessMemory_a25e {
  strings:
    $key_a25e = { f5 2c [2] c7 0e [2] c1 3b [2] ef 3b [2] d0 27 }

  condition:
    any of them
}