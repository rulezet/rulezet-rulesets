rule TTP_XOR_WriteProcessMemory_264b {
  strings:
    $key_264b = { 71 39 [2] 43 1b [2] 45 2e [2] 6b 2e [2] 54 32 }

  condition:
    any of them
}