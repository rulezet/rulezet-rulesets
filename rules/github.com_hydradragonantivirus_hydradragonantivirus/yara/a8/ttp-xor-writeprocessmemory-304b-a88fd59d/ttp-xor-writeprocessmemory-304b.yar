rule TTP_XOR_WriteProcessMemory_304b {
  strings:
    $key_304b = { 67 39 [2] 55 1b [2] 53 2e [2] 7d 2e [2] 42 32 }

  condition:
    any of them
}