rule TTP_XOR_WriteProcessMemory_a67f {
  strings:
    $key_a67f = { f1 0d [2] c3 2f [2] c5 1a [2] eb 1a [2] d4 06 }

  condition:
    any of them
}