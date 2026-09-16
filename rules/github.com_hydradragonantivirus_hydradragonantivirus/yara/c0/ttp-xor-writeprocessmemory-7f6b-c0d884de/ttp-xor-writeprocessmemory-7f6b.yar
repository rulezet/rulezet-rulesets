rule TTP_XOR_WriteProcessMemory_7f6b {
  strings:
    $key_7f6b = { 28 19 [2] 1a 3b [2] 1c 0e [2] 32 0e [2] 0d 12 }

  condition:
    any of them
}