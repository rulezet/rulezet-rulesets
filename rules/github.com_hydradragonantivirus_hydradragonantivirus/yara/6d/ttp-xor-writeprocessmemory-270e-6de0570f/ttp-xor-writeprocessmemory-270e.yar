rule TTP_XOR_WriteProcessMemory_270e {
  strings:
    $key_270e = { 70 7c [2] 42 5e [2] 44 6b [2] 6a 6b [2] 55 77 }

  condition:
    any of them
}