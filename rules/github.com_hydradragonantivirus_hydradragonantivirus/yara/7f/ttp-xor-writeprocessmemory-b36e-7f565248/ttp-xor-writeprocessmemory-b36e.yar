rule TTP_XOR_WriteProcessMemory_b36e {
  strings:
    $key_b36e = { e4 1c [2] d6 3e [2] d0 0b [2] fe 0b [2] c1 17 }

  condition:
    any of them
}