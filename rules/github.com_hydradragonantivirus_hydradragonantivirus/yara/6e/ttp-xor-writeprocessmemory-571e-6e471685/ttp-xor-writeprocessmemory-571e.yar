rule TTP_XOR_WriteProcessMemory_571e {
  strings:
    $key_571e = { 00 6c [2] 32 4e [2] 34 7b [2] 1a 7b [2] 25 67 }

  condition:
    any of them
}