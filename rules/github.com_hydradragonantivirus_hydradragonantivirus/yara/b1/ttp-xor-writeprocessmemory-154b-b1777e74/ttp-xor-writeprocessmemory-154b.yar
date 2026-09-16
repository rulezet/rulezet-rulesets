rule TTP_XOR_WriteProcessMemory_154b {
  strings:
    $key_154b = { 42 39 [2] 70 1b [2] 76 2e [2] 58 2e [2] 67 32 }

  condition:
    any of them
}