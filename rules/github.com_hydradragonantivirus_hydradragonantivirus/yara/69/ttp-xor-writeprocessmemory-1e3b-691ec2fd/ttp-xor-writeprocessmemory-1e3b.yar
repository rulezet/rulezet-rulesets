rule TTP_XOR_WriteProcessMemory_1e3b {
  strings:
    $key_1e3b = { 49 49 [2] 7b 6b [2] 7d 5e [2] 53 5e [2] 6c 42 }

  condition:
    any of them
}