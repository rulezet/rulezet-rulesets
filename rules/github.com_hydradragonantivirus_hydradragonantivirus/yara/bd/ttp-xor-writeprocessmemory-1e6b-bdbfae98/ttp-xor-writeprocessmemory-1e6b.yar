rule TTP_XOR_WriteProcessMemory_1e6b {
  strings:
    $key_1e6b = { 49 19 [2] 7b 3b [2] 7d 0e [2] 53 0e [2] 6c 12 }

  condition:
    any of them
}