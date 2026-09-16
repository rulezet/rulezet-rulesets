rule TTP_XOR_WriteProcessMemory_636b {
  strings:
    $key_636b = { 34 19 [2] 06 3b [2] 00 0e [2] 2e 0e [2] 11 12 }

  condition:
    any of them
}