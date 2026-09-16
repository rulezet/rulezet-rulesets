rule TTP_XOR_WriteProcessMemory_651e {
  strings:
    $key_651e = { 32 6c [2] 00 4e [2] 06 7b [2] 28 7b [2] 17 67 }

  condition:
    any of them
}