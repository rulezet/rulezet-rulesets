rule TTP_XOR_WriteProcessMemory_a66c {
  strings:
    $key_a66c = { f1 1e [2] c3 3c [2] c5 09 [2] eb 09 [2] d4 15 }

  condition:
    any of them
}