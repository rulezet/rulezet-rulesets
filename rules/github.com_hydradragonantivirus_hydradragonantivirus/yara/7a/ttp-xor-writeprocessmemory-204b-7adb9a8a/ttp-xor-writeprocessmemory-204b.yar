rule TTP_XOR_WriteProcessMemory_204b {
  strings:
    $key_204b = { 77 39 [2] 45 1b [2] 43 2e [2] 6d 2e [2] 52 32 }

  condition:
    any of them
}