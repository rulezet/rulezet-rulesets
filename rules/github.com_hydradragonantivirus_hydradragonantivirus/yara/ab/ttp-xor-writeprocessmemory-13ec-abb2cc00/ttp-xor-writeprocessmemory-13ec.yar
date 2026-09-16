rule TTP_XOR_WriteProcessMemory_13ec {
  strings:
    $key_13ec = { 44 9e [2] 76 bc [2] 70 89 [2] 5e 89 [2] 61 95 }

  condition:
    any of them
}