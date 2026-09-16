rule TTP_XOR_WriteProcessMemory_550e {
  strings:
    $key_550e = { 02 7c [2] 30 5e [2] 36 6b [2] 18 6b [2] 27 77 }

  condition:
    any of them
}