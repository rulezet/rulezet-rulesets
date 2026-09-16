rule TTP_XOR_WriteProcessMemory_9645 {
  strings:
    $key_9645 = { c1 37 [2] f3 15 [2] f5 20 [2] db 20 [2] e4 3c }

  condition:
    any of them
}