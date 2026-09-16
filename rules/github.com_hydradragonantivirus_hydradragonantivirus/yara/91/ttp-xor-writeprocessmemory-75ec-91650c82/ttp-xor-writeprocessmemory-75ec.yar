rule TTP_XOR_WriteProcessMemory_75ec {
  strings:
    $key_75ec = { 22 9e [2] 10 bc [2] 16 89 [2] 38 89 [2] 07 95 }

  condition:
    any of them
}