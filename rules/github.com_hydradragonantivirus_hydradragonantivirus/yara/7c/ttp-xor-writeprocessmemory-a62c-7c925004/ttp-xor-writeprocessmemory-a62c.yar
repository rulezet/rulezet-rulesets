rule TTP_XOR_WriteProcessMemory_a62c {
  strings:
    $key_a62c = { f1 5e [2] c3 7c [2] c5 49 [2] eb 49 [2] d4 55 }

  condition:
    any of them
}