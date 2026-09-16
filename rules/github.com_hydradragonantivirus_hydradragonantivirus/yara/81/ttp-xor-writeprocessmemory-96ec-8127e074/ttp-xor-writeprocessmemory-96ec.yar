rule TTP_XOR_WriteProcessMemory_96ec {
  strings:
    $key_96ec = { c1 9e [2] f3 bc [2] f5 89 [2] db 89 [2] e4 95 }

  condition:
    any of them
}