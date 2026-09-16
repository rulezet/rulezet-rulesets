rule TTP_XOR_WriteProcessMemory_94ec {
  strings:
    $key_94ec = { c3 9e [2] f1 bc [2] f7 89 [2] d9 89 [2] e6 95 }

  condition:
    any of them
}