rule TTP_XOR_WriteProcessMemory_63ec {
  strings:
    $key_63ec = { 34 9e [2] 06 bc [2] 00 89 [2] 2e 89 [2] 11 95 }

  condition:
    any of them
}