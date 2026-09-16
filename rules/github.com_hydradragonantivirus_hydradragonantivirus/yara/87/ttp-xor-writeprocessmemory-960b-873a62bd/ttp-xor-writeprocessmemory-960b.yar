rule TTP_XOR_WriteProcessMemory_960b {
  strings:
    $key_960b = { c1 79 [2] f3 5b [2] f5 6e [2] db 6e [2] e4 72 }

  condition:
    any of them
}