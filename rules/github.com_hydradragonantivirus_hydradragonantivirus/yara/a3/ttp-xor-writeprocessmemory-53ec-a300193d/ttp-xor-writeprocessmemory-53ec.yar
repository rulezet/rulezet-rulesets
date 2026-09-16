rule TTP_XOR_WriteProcessMemory_53ec {
  strings:
    $key_53ec = { 04 9e [2] 36 bc [2] 30 89 [2] 1e 89 [2] 21 95 }

  condition:
    any of them
}