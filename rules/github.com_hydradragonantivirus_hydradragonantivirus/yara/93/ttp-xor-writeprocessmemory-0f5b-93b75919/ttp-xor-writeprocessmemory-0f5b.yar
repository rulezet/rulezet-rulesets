rule TTP_XOR_WriteProcessMemory_0f5b {
  strings:
    $key_0f5b = { 58 29 [2] 6a 0b [2] 6c 3e [2] 42 3e [2] 7d 22 }

  condition:
    any of them
}