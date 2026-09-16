rule TTP_XOR_WriteProcessMemory_a46c {
  strings:
    $key_a46c = { f3 1e [2] c1 3c [2] c7 09 [2] e9 09 [2] d6 15 }

  condition:
    any of them
}