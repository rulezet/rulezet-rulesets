rule TTP_XOR_WriteProcessMemory_a65c {
  strings:
    $key_a65c = { f1 2e [2] c3 0c [2] c5 39 [2] eb 39 [2] d4 25 }

  condition:
    any of them
}