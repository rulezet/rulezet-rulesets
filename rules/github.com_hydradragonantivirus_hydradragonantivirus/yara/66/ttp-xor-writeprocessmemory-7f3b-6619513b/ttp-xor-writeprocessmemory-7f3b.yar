rule TTP_XOR_WriteProcessMemory_7f3b {
  strings:
    $key_7f3b = { 28 49 [2] 1a 6b [2] 1c 5e [2] 32 5e [2] 0d 42 }

  condition:
    any of them
}