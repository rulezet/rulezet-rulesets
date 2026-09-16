rule TTP_XOR_WriteProcessMemory_146b {
  strings:
    $key_146b = { 43 19 [2] 71 3b [2] 77 0e [2] 59 0e [2] 66 12 }

  condition:
    any of them
}