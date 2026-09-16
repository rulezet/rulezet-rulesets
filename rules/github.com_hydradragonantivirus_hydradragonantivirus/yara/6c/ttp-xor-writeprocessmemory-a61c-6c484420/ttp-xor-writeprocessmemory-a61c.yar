rule TTP_XOR_WriteProcessMemory_a61c {
  strings:
    $key_a61c = { f1 6e [2] c3 4c [2] c5 79 [2] eb 79 [2] d4 65 }

  condition:
    any of them
}