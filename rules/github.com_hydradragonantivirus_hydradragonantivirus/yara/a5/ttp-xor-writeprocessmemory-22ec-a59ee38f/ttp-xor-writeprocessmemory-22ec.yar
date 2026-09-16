rule TTP_XOR_WriteProcessMemory_22ec {
  strings:
    $key_22ec = { 75 9e [2] 47 bc [2] 41 89 [2] 6f 89 [2] 50 95 }

  condition:
    any of them
}