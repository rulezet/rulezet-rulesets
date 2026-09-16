rule TTP_XOR_WriteProcessMemory_a62d {
  strings:
    $key_a62d = { f1 5f [2] c3 7d [2] c5 48 [2] eb 48 [2] d4 54 }

  condition:
    any of them
}