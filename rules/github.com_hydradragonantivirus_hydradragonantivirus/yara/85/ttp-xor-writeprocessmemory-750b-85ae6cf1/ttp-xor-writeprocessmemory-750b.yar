rule TTP_XOR_WriteProcessMemory_750b {
  strings:
    $key_750b = { 22 79 [2] 10 5b [2] 16 6e [2] 38 6e [2] 07 72 }

  condition:
    any of them
}