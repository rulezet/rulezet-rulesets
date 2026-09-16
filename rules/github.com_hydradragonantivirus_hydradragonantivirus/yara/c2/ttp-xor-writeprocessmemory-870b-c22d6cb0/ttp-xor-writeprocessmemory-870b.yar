rule TTP_XOR_WriteProcessMemory_870b {
  strings:
    $key_870b = { d0 79 [2] e2 5b [2] e4 6e [2] ca 6e [2] f5 72 }

  condition:
    any of them
}