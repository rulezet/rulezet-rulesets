rule TTP_XOR_WriteProcessMemory_b36f {
  strings:
    $key_b36f = { e4 1d [2] d6 3f [2] d0 0a [2] fe 0a [2] c1 16 }

  condition:
    any of them
}