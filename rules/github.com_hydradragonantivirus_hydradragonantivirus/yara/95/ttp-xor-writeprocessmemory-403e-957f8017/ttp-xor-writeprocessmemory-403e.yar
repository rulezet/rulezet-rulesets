rule TTP_XOR_WriteProcessMemory_403e {
  strings:
    $key_403e = { 17 4c [2] 25 6e [2] 23 5b [2] 0d 5b [2] 32 47 }

  condition:
    any of them
}