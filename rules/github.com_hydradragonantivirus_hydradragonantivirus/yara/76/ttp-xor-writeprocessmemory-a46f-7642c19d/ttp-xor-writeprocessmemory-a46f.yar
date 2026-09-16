rule TTP_XOR_WriteProcessMemory_a46f {
  strings:
    $key_a46f = { f3 1d [2] c1 3f [2] c7 0a [2] e9 0a [2] d6 16 }

  condition:
    any of them
}