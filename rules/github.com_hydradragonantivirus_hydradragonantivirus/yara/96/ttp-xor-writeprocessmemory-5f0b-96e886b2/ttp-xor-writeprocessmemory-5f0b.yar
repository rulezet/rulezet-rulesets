rule TTP_XOR_WriteProcessMemory_5f0b {
  strings:
    $key_5f0b = { 08 79 [2] 3a 5b [2] 3c 6e [2] 12 6e [2] 2d 72 }

  condition:
    any of them
}