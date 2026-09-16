rule TTP_XOR_WriteProcessMemory_0bbc {
  strings:
    $key_0bbc = { 5c ce [2] 6e ec [2] 68 d9 [2] 46 d9 [2] 79 c5 }

  condition:
    any of them
}