rule TTP_XOR_WriteProcessMemory_a61e {
  strings:
    $key_a61e = { f1 6c [2] c3 4e [2] c5 7b [2] eb 7b [2] d4 67 }

  condition:
    any of them
}