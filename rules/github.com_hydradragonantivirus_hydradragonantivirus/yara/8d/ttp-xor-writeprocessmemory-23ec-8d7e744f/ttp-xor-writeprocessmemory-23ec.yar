rule TTP_XOR_WriteProcessMemory_23ec {
  strings:
    $key_23ec = { 74 9e [2] 46 bc [2] 40 89 [2] 6e 89 [2] 51 95 }

  condition:
    any of them
}