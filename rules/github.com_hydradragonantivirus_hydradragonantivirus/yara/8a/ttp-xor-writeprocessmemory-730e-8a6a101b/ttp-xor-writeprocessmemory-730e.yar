rule TTP_XOR_WriteProcessMemory_730e {
  strings:
    $key_730e = { 24 7c [2] 16 5e [2] 10 6b [2] 3e 6b [2] 01 77 }

  condition:
    any of them
}