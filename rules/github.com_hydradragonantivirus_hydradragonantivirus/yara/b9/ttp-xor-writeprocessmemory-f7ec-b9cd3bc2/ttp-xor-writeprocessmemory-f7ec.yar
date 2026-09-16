rule TTP_XOR_WriteProcessMemory_f7ec {
  strings:
    $key_f7ec = { a0 9e [2] 92 bc [2] 94 89 [2] ba 89 [2] 85 95 }

  condition:
    any of them
}