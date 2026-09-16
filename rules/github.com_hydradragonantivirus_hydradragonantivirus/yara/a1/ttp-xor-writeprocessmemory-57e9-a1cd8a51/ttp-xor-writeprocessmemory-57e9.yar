rule TTP_XOR_WriteProcessMemory_57e9 {
  strings:
    $key_57e9 = { 00 9b [2] 32 b9 [2] 34 8c [2] 1a 8c [2] 25 90 }

  condition:
    any of them
}