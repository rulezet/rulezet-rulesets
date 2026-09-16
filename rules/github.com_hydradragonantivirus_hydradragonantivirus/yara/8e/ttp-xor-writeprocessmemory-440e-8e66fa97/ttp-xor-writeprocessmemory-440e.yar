rule TTP_XOR_WriteProcessMemory_440e {
  strings:
    $key_440e = { 13 7c [2] 21 5e [2] 27 6b [2] 09 6b [2] 36 77 }

  condition:
    any of them
}