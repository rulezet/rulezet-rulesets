rule TTP_XOR_WriteProcessMemory_967b {
  strings:
    $key_967b = { c1 09 [2] f3 2b [2] f5 1e [2] db 1e [2] e4 02 }

  condition:
    any of them
}