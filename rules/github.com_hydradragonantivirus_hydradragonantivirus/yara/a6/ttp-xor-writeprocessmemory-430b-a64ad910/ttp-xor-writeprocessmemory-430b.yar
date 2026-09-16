rule TTP_XOR_WriteProcessMemory_430b {
  strings:
    $key_430b = { 14 79 [2] 26 5b [2] 20 6e [2] 0e 6e [2] 31 72 }

  condition:
    any of them
}