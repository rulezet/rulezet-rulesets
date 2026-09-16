rule TTP_XOR_WriteProcessMemory_189b {
  strings:
    $key_189b = { 4f e9 [2] 7d cb [2] 7b fe [2] 55 fe [2] 6a e2 }

  condition:
    any of them
}