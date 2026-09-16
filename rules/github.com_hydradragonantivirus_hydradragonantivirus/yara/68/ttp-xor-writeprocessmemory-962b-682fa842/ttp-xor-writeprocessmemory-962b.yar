rule TTP_XOR_WriteProcessMemory_962b {
  strings:
    $key_962b = { c1 59 [2] f3 7b [2] f5 4e [2] db 4e [2] e4 52 }

  condition:
    any of them
}