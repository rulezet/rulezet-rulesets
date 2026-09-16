rule TTP_XOR_WriteProcessMemory_a65e {
  strings:
    $key_a65e = { f1 2c [2] c3 0e [2] c5 3b [2] eb 3b [2] d4 27 }

  condition:
    any of them
}