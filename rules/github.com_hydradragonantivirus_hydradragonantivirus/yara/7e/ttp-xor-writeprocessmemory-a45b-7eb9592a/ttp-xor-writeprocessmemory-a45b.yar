rule TTP_XOR_WriteProcessMemory_a45b {
  strings:
    $key_a45b = { f3 29 [2] c1 0b [2] c7 3e [2] e9 3e [2] d6 22 }

  condition:
    any of them
}