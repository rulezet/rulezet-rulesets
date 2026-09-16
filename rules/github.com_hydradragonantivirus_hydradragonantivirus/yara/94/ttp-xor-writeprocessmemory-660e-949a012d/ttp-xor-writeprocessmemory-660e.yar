rule TTP_XOR_WriteProcessMemory_660e {
  strings:
    $key_660e = { 31 7c [2] 03 5e [2] 05 6b [2] 2b 6b [2] 14 77 }

  condition:
    any of them
}