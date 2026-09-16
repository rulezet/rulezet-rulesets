rule TTP_XOR_WriteProcessMemory_430e {
  strings:
    $key_430e = { 14 7c [2] 26 5e [2] 20 6b [2] 0e 6b [2] 31 77 }

  condition:
    any of them
}