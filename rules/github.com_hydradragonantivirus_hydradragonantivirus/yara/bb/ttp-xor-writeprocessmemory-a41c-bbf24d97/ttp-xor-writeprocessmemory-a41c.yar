rule TTP_XOR_WriteProcessMemory_a41c {
  strings:
    $key_a41c = { f3 6e [2] c1 4c [2] c7 79 [2] e9 79 [2] d6 65 }

  condition:
    any of them
}