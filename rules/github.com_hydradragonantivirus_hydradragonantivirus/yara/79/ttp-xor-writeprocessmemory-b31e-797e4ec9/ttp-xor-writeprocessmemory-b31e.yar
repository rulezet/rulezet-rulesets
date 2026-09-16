rule TTP_XOR_WriteProcessMemory_b31e {
  strings:
    $key_b31e = { e4 6c [2] d6 4e [2] d0 7b [2] fe 7b [2] c1 67 }

  condition:
    any of them
}