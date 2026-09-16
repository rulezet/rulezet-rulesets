rule TTP_XOR_WriteProcessMemory_107b {
  strings:
    $key_107b = { 47 09 [2] 75 2b [2] 73 1e [2] 5d 1e [2] 62 02 }

  condition:
    any of them
}