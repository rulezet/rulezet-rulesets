rule TTP_XOR_WriteProcessMemory_0f6b {
  strings:
    $key_0f6b = { 58 19 [2] 6a 3b [2] 6c 0e [2] 42 0e [2] 7d 12 }

  condition:
    any of them
}