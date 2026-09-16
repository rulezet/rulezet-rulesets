rule TTP_XOR_WriteProcessMemory_97ec {
  strings:
    $key_97ec = { c0 9e [2] f2 bc [2] f4 89 [2] da 89 [2] e5 95 }

  condition:
    any of them
}