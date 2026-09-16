rule TTP_XOR_WriteProcessMemory_b35f {
  strings:
    $key_b35f = { e4 2d [2] d6 0f [2] d0 3a [2] fe 3a [2] c1 26 }

  condition:
    any of them
}