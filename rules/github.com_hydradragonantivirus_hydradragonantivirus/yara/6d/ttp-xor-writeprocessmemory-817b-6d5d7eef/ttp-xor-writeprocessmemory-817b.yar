rule TTP_XOR_WriteProcessMemory_817b {
  strings:
    $key_817b = { d6 09 [2] e4 2b [2] e2 1e [2] cc 1e [2] f3 02 }

  condition:
    any of them
}