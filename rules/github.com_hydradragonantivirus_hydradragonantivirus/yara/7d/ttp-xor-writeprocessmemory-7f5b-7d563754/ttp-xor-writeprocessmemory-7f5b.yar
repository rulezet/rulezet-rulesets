rule TTP_XOR_WriteProcessMemory_7f5b {
  strings:
    $key_7f5b = { 28 29 [2] 1a 0b [2] 1c 3e [2] 32 3e [2] 0d 22 }

  condition:
    any of them
}