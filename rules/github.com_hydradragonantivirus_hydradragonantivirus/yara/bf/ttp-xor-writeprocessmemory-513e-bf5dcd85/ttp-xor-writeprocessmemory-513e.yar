rule TTP_XOR_WriteProcessMemory_513e {
  strings:
    $key_513e = { 06 4c [2] 34 6e [2] 32 5b [2] 1c 5b [2] 23 47 }

  condition:
    any of them
}