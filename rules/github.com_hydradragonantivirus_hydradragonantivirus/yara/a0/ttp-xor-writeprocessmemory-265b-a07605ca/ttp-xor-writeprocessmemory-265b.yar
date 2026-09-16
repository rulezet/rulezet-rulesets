rule TTP_XOR_WriteProcessMemory_265b {
  strings:
    $key_265b = { 71 29 [2] 43 0b [2] 45 3e [2] 6b 3e [2] 54 22 }

  condition:
    any of them
}