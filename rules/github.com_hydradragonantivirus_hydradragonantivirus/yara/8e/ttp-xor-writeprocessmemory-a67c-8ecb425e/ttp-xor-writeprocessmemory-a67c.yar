rule TTP_XOR_WriteProcessMemory_a67c {
  strings:
    $key_a67c = { f1 0e [2] c3 2c [2] c5 19 [2] eb 19 [2] d4 05 }

  condition:
    any of them
}