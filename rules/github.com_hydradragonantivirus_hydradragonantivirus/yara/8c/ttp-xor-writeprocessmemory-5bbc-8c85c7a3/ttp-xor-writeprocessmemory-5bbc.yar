rule TTP_XOR_WriteProcessMemory_5bbc {
  strings:
    $key_5bbc = { 0c ce [2] 3e ec [2] 38 d9 [2] 16 d9 [2] 29 c5 }

  condition:
    any of them
}