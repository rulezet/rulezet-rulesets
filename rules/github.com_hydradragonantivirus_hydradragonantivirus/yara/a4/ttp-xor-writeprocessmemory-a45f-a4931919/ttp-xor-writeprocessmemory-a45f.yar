rule TTP_XOR_WriteProcessMemory_a45f {
  strings:
    $key_a45f = { f3 2d [2] c1 0f [2] c7 3a [2] e9 3a [2] d6 26 }

  condition:
    any of them
}