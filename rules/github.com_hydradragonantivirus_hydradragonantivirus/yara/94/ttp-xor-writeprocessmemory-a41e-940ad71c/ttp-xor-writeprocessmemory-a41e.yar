rule TTP_XOR_WriteProcessMemory_a41e {
  strings:
    $key_a41e = { f3 6c [2] c1 4e [2] c7 7b [2] e9 7b [2] d6 67 }

  condition:
    any of them
}