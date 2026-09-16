rule TTP_XOR_WriteProcessMemory_e5ec {
  strings:
    $key_e5ec = { b2 9e [2] 80 bc [2] 86 89 [2] a8 89 [2] 97 95 }

  condition:
    any of them
}