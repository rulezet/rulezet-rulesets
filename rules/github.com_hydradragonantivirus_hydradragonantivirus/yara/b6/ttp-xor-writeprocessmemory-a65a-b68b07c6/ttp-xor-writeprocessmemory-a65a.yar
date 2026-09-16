rule TTP_XOR_WriteProcessMemory_a65a {
  strings:
    $key_a65a = { f1 28 [2] c3 0a [2] c5 3f [2] eb 3f [2] d4 23 }

  condition:
    any of them
}