rule TTP_XOR_WriteProcessMemory_727b {
  strings:
    $key_727b = { 25 09 [2] 17 2b [2] 11 1e [2] 3f 1e [2] 00 02 }

  condition:
    any of them
}