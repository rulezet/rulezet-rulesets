rule TTP_XOR_WriteProcessMemory_470e {
  strings:
    $key_470e = { 10 7c [2] 22 5e [2] 24 6b [2] 0a 6b [2] 35 77 }

  condition:
    any of them
}