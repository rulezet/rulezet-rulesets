rule TTP_XOR_WriteProcessMemory_576b {
  strings:
    $key_576b = { 00 19 [2] 32 3b [2] 34 0e [2] 1a 0e [2] 25 12 }

  condition:
    any of them
}