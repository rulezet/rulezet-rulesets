rule TTP_XOR_WriteProcessMemory_a6ec {
  strings:
    $key_a6ec = { f1 9e [2] c3 bc [2] c5 89 [2] eb 89 [2] d4 95 }

  condition:
    any of them
}