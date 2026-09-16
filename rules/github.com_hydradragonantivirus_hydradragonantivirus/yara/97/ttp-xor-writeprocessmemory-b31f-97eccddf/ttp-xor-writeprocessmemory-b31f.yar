rule TTP_XOR_WriteProcessMemory_b31f {
  strings:
    $key_b31f = { e4 6d [2] d6 4f [2] d0 7a [2] fe 7a [2] c1 66 }

  condition:
    any of them
}