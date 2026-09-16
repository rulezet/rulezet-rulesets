rule TTP_XOR_WriteProcessMemory_340e {
  strings:
    $key_340e = { 63 7c [2] 51 5e [2] 57 6b [2] 79 6b [2] 46 77 }

  condition:
    any of them
}