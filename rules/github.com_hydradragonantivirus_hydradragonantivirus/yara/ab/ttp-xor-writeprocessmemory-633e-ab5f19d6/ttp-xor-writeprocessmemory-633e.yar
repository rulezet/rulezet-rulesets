rule TTP_XOR_WriteProcessMemory_633e {
  strings:
    $key_633e = { 34 4c [2] 06 6e [2] 00 5b [2] 2e 5b [2] 11 47 }

  condition:
    any of them
}