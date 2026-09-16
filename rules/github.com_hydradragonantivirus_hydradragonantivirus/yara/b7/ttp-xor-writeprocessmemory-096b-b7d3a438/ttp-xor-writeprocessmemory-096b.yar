rule TTP_XOR_WriteProcessMemory_096b {
  strings:
    $key_096b = { 5e 19 [2] 6c 3b [2] 6a 0e [2] 44 0e [2] 7b 12 }

  condition:
    any of them
}