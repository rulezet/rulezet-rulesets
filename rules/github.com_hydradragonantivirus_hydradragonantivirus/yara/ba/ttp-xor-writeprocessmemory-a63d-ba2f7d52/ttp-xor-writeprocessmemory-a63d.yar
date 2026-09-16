rule TTP_XOR_WriteProcessMemory_a63d {
  strings:
    $key_a63d = { f1 4f [2] c3 6d [2] c5 58 [2] eb 58 [2] d4 44 }

  condition:
    any of them
}