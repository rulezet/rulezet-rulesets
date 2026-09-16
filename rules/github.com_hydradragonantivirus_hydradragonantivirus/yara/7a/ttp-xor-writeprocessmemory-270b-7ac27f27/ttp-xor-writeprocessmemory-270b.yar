rule TTP_XOR_WriteProcessMemory_270b {
  strings:
    $key_270b = { 70 79 [2] 42 5b [2] 44 6e [2] 6a 6e [2] 55 72 }

  condition:
    any of them
}