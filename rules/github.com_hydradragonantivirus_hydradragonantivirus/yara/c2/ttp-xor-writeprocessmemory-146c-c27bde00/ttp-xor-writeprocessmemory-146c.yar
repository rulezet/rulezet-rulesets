rule TTP_XOR_WriteProcessMemory_146c {
  strings:
    $key_146c = { 43 1e [2] 71 3c [2] 77 09 [2] 59 09 [2] 66 15 }

  condition:
    any of them
}