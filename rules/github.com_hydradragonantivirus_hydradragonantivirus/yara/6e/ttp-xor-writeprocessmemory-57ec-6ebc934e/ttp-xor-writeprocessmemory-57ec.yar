rule TTP_XOR_WriteProcessMemory_57ec {
  strings:
    $key_57ec = { 00 9e [2] 32 bc [2] 34 89 [2] 1a 89 [2] 25 95 }

  condition:
    any of them
}