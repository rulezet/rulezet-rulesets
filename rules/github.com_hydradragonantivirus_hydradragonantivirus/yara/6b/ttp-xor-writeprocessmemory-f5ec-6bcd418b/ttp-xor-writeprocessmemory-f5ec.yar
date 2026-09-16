rule TTP_XOR_WriteProcessMemory_f5ec {
  strings:
    $key_f5ec = { a2 9e [2] 90 bc [2] 96 89 [2] b8 89 [2] 87 95 }

  condition:
    any of them
}