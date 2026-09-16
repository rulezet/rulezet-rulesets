rule TTP_XOR_WriteProcessMemory_7bbc {
  strings:
    $key_7bbc = { 2c ce [2] 1e ec [2] 18 d9 [2] 36 d9 [2] 09 c5 }

  condition:
    any of them
}