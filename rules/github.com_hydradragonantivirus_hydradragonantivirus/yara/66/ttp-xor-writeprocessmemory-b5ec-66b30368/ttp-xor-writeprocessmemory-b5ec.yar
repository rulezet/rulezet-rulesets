rule TTP_XOR_WriteProcessMemory_b5ec {
  strings:
    $key_b5ec = { e2 9e [2] d0 bc [2] d6 89 [2] f8 89 [2] c7 95 }

  condition:
    any of them
}