rule TTP_XOR_WriteProcessMemory_770e {
  strings:
    $key_770e = { 20 7c [2] 12 5e [2] 14 6b [2] 3a 6b [2] 05 77 }

  condition:
    any of them
}