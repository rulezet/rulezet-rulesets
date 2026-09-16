rule TTP_XOR_WriteProcessMemory_3a2b {
  strings:
    $key_3a2b = { 6d 59 [2] 5f 7b [2] 59 4e [2] 77 4e [2] 48 52 }

  condition:
    any of them
}