rule TTP_XOR_WriteProcessMemory_305b {
  strings:
    $key_305b = { 67 29 [2] 55 0b [2] 53 3e [2] 7d 3e [2] 42 22 }

  condition:
    any of them
}