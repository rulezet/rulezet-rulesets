rule TTP_XOR_WriteProcessMemory_5f6b {
  strings:
    $key_5f6b = { 08 19 [2] 3a 3b [2] 3c 0e [2] 12 0e [2] 2d 12 }

  condition:
    any of them
}