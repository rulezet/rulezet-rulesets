rule TTP_XOR_WriteProcessMemory_5f4b {
  strings:
    $key_5f4b = { 08 39 [2] 3a 1b [2] 3c 2e [2] 12 2e [2] 2d 32 }

  condition:
    any of them
}