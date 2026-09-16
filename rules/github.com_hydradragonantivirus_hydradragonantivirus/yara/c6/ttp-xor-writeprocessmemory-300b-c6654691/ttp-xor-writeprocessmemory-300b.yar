rule TTP_XOR_WriteProcessMemory_300b {
  strings:
    $key_300b = { 67 79 [2] 55 5b [2] 53 6e [2] 7d 6e [2] 42 72 }

  condition:
    any of them
}