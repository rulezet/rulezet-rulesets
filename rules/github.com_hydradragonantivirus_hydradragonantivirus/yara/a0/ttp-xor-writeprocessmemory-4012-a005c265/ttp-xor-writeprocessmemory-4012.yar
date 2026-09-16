rule TTP_XOR_WriteProcessMemory_4012 {
  strings:
    $key_4012 = { 17 60 [2] 25 42 [2] 23 77 [2] 0d 77 [2] 32 6b }

  condition:
    any of them
}