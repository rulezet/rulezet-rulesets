rule TTP_XOR_WriteProcessMemory_07ec {
  strings:
    $key_07ec = { 50 9e [2] 62 bc [2] 64 89 [2] 4a 89 [2] 75 95 }

  condition:
    any of them
}