rule TTP_XOR_WriteProcessMemory_084b {
  strings:
    $key_084b = { 5f 39 [2] 6d 1b [2] 6b 2e [2] 45 2e [2] 7a 32 }

  condition:
    any of them
}