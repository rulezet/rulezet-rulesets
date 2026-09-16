rule TTP_XOR_WriteProcessMemory_1e7b {
  strings:
    $key_1e7b = { 49 09 [2] 7b 2b [2] 7d 1e [2] 53 1e [2] 6c 02 }

  condition:
    any of them
}