rule TTP_XOR_WriteProcessMemory_764b {
  strings:
    $key_764b = { 21 39 [2] 13 1b [2] 15 2e [2] 3b 2e [2] 04 32 }

  condition:
    any of them
}