rule TTP_XOR_WriteProcessMemory_1d6b {
  strings:
    $key_1d6b = { 4a 19 [2] 78 3b [2] 7e 0e [2] 50 0e [2] 6f 12 }

  condition:
    any of them
}