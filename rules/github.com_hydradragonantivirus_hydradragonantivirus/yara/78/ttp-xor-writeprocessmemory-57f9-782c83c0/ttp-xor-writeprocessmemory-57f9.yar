rule TTP_XOR_WriteProcessMemory_57f9 {
  strings:
    $key_57f9 = { 00 8b [2] 32 a9 [2] 34 9c [2] 1a 9c [2] 25 80 }

  condition:
    any of them
}