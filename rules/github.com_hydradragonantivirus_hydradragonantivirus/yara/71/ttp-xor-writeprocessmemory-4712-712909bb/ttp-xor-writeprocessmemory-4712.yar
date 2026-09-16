rule TTP_XOR_WriteProcessMemory_4712 {
  strings:
    $key_4712 = { 10 60 [2] 22 42 [2] 24 77 [2] 0a 77 [2] 35 6b }

  condition:
    any of them
}