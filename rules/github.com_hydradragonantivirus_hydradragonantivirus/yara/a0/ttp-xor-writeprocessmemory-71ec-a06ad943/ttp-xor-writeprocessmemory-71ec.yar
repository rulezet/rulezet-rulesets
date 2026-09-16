rule TTP_XOR_WriteProcessMemory_71ec {
  strings:
    $key_71ec = { 26 9e [2] 14 bc [2] 12 89 [2] 3c 89 [2] 03 95 }

  condition:
    any of them
}