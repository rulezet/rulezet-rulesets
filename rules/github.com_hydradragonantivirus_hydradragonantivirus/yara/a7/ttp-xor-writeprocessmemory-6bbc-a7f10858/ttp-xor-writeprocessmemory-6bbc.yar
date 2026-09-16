rule TTP_XOR_WriteProcessMemory_6bbc {
  strings:
    $key_6bbc = { 3c ce [2] 0e ec [2] 08 d9 [2] 26 d9 [2] 19 c5 }

  condition:
    any of them
}