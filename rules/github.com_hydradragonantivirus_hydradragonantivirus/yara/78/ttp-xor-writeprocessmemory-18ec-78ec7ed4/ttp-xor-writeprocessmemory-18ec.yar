rule TTP_XOR_WriteProcessMemory_18ec {
  strings:
    $key_18ec = { 4f 9e [2] 7d bc [2] 7b 89 [2] 55 89 [2] 6a 95 }

  condition:
    any of them
}