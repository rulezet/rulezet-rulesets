rule TTP_XOR_WriteProcessMemory_a67d {
  strings:
    $key_a67d = { f1 0f [2] c3 2d [2] c5 18 [2] eb 18 [2] d4 04 }

  condition:
    any of them
}