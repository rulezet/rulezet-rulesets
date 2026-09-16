rule TTP_XOR_WriteProcessMemory_030b {
  strings:
    $key_030b = { 54 79 [2] 66 5b [2] 60 6e [2] 4e 6e [2] 71 72 }

  condition:
    any of them
}