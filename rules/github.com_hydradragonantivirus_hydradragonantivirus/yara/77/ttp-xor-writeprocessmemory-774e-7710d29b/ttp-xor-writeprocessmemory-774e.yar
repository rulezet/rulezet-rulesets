rule TTP_XOR_WriteProcessMemory_774e {
  strings:
    $key_774e = { 20 3c [2] 12 1e [2] 14 2b [2] 3a 2b [2] 05 37 }

  condition:
    any of them
}