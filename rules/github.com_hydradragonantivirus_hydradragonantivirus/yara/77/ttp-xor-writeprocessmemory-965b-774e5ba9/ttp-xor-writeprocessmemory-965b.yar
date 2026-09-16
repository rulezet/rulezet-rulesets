rule TTP_XOR_WriteProcessMemory_965b {
  strings:
    $key_965b = { c1 29 [2] f3 0b [2] f5 3e [2] db 3e [2] e4 22 }

  condition:
    any of them
}