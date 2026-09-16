rule TTP_XOR_WriteProcessMemory_574e {
  strings:
    $key_574e = { 00 3c [2] 32 1e [2] 34 2b [2] 1a 2b [2] 25 37 }

  condition:
    any of them
}