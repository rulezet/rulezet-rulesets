rule TTP_XOR_WriteProcessMemory_b4ec {
  strings:
    $key_b4ec = { e3 9e [2] d1 bc [2] d7 89 [2] f9 89 [2] c6 95 }

  condition:
    any of them
}