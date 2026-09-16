rule TTP_XOR_WriteProcessMemory_a27f {
  strings:
    $key_a27f = { f5 0d [2] c7 2f [2] c1 1a [2] ef 1a [2] d0 06 }

  condition:
    any of them
}