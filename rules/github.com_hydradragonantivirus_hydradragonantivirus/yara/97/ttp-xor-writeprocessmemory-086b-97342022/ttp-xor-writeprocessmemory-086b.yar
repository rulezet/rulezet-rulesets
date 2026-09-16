rule TTP_XOR_WriteProcessMemory_086b {
  strings:
    $key_086b = { 5f 19 [2] 6d 3b [2] 6b 0e [2] 45 0e [2] 7a 12 }

  condition:
    any of them
}