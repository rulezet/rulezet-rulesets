rule TTP_XOR_WriteProcessMemory_805b {
  strings:
    $key_805b = { d7 29 [2] e5 0b [2] e3 3e [2] cd 3e [2] f2 22 }

  condition:
    any of them
}