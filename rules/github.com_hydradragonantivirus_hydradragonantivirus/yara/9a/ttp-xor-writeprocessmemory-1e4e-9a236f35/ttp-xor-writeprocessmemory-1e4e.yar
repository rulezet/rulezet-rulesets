rule TTP_XOR_WriteProcessMemory_1e4e {
  strings:
    $key_1e4e = { 49 3c [2] 7b 1e [2] 7d 2b [2] 53 2b [2] 6c 37 }

  condition:
    any of them
}