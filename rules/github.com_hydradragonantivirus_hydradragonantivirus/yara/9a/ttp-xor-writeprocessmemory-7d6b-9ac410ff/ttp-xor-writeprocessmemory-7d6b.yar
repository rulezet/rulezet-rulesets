rule TTP_XOR_WriteProcessMemory_7d6b {
  strings:
    $key_7d6b = { 2a 19 [2] 18 3b [2] 1e 0e [2] 30 0e [2] 0f 12 }

  condition:
    any of them
}