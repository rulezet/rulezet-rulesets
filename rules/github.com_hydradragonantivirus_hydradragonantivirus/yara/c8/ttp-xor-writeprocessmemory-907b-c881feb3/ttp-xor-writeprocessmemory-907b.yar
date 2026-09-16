rule TTP_XOR_WriteProcessMemory_907b {
  strings:
    $key_907b = { c7 09 [2] f5 2b [2] f3 1e [2] dd 1e [2] e2 02 }

  condition:
    any of them
}