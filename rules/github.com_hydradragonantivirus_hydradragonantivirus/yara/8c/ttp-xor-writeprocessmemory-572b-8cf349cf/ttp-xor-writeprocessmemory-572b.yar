rule TTP_XOR_WriteProcessMemory_572b {
  strings:
    $key_572b = { 00 59 [2] 32 7b [2] 34 4e [2] 1a 4e [2] 25 52 }

  condition:
    any of them
}