rule TTP_XOR_WriteProcessMemory_5c6b {
  strings:
    $key_5c6b = { 0b 19 [2] 39 3b [2] 3f 0e [2] 11 0e [2] 2e 12 }

  condition:
    any of them
}