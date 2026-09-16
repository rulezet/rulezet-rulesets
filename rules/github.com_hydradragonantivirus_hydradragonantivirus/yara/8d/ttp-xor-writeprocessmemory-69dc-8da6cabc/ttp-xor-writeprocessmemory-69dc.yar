rule TTP_XOR_WriteProcessMemory_69dc {
  strings:
    $key_69dc = { 3e ae [2] 0c 8c [2] 0a b9 [2] 24 b9 [2] 1b a5 }

  condition:
    any of them
}