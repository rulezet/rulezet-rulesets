rule TTP_XOR_WriteProcessMemory_a25f {
  strings:
    $key_a25f = { f5 2d [2] c7 0f [2] c1 3a [2] ef 3a [2] d0 26 }

  condition:
    any of them
}