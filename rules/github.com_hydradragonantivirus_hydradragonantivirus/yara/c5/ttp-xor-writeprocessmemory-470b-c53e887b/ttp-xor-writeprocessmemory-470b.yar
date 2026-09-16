rule TTP_XOR_WriteProcessMemory_470b {
  strings:
    $key_470b = { 10 79 [2] 22 5b [2] 24 6e [2] 0a 6e [2] 35 72 }

  condition:
    any of them
}