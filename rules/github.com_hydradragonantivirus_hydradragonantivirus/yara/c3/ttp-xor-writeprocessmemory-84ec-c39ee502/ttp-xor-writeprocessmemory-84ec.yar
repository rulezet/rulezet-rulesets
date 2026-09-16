rule TTP_XOR_WriteProcessMemory_84ec {
  strings:
    $key_84ec = { d3 9e [2] e1 bc [2] e7 89 [2] c9 89 [2] f6 95 }

  condition:
    any of them
}