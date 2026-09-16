rule TTP_XOR_WriteProcessMemory_1e4b {
  strings:
    $key_1e4b = { 49 39 [2] 7b 1b [2] 7d 2e [2] 53 2e [2] 6c 32 }

  condition:
    any of them
}