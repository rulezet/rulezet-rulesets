rule TTP_XOR_WriteProcessMemory_41ec {
  strings:
    $key_41ec = { 16 9e [2] 24 bc [2] 22 89 [2] 0c 89 [2] 33 95 }

  condition:
    any of them
}