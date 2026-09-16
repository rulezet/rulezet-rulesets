rule TTP_XOR_WriteProcessMemory_0f0b {
  strings:
    $key_0f0b = { 58 79 [2] 6a 5b [2] 6c 6e [2] 42 6e [2] 7d 72 }

  condition:
    any of them
}