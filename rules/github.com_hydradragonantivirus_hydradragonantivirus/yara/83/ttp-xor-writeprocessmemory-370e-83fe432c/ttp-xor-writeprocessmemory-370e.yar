rule TTP_XOR_WriteProcessMemory_370e {
  strings:
    $key_370e = { 60 7c [2] 52 5e [2] 54 6b [2] 7a 6b [2] 45 77 }

  condition:
    any of them
}