rule TTP_XOR_WriteProcessMemory_a0ec {
  strings:
    $key_a0ec = { f7 9e [2] c5 bc [2] c3 89 [2] ed 89 [2] d2 95 }

  condition:
    any of them
}