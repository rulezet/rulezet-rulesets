rule TTP_XOR_WriteProcessMemory_a60f {
  strings:
    $key_a60f = { f1 7d [2] c3 5f [2] c5 6a [2] eb 6a [2] d4 76 }

  condition:
    any of them
}