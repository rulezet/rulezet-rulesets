rule TTP_XOR_WriteProcessMemory_b36c {
  strings:
    $key_b36c = { e4 1e [2] d6 3c [2] d0 09 [2] fe 09 [2] c1 15 }

  condition:
    any of them
}