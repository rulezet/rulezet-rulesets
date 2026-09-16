rule TTP_XOR_WriteProcessMemory_570b {
  strings:
    $key_570b = { 00 79 [2] 32 5b [2] 34 6e [2] 1a 6e [2] 25 72 }

  condition:
    any of them
}