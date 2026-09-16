rule TTP_XOR_WriteProcessMemory_85ec {
  strings:
    $key_85ec = { d2 9e [2] e0 bc [2] e6 89 [2] c8 89 [2] f7 95 }

  condition:
    any of them
}