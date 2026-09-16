rule TTP_XOR_WriteProcessMemory_ebbc {
  strings:
    $key_ebbc = { bc ce [2] 8e ec [2] 88 d9 [2] a6 d9 [2] 99 c5 }

  condition:
    any of them
}