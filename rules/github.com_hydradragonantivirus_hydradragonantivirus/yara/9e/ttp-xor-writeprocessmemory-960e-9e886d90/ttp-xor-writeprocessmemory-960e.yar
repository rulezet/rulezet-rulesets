rule TTP_XOR_WriteProcessMemory_960e {
  strings:
    $key_960e = { c1 7c [2] f3 5e [2] f5 6b [2] db 6b [2] e4 77 }

  condition:
    any of them
}