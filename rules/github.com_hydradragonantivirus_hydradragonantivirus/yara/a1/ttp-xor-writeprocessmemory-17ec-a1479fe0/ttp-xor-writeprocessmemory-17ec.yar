rule TTP_XOR_WriteProcessMemory_17ec {
  strings:
    $key_17ec = { 40 9e [2] 72 bc [2] 74 89 [2] 5a 89 [2] 65 95 }

  condition:
    any of them
}