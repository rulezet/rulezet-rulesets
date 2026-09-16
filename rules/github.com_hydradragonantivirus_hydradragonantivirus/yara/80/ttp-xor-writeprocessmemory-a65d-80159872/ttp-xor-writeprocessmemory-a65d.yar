rule TTP_XOR_WriteProcessMemory_a65d {
  strings:
    $key_a65d = { f1 2f [2] c3 0d [2] c5 38 [2] eb 38 [2] d4 24 }

  condition:
    any of them
}