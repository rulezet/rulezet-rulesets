rule TTP_XOR_WriteProcessMemory_590b {
  strings:
    $key_590b = { 0e 79 [2] 3c 5b [2] 3a 6e [2] 14 6e [2] 2b 72 }

  condition:
    any of them
}