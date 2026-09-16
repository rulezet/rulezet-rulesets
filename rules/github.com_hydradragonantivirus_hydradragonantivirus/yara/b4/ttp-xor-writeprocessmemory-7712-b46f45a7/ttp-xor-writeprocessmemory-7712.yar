rule TTP_XOR_WriteProcessMemory_7712 {
  strings:
    $key_7712 = { 20 60 [2] 12 42 [2] 14 77 [2] 3a 77 [2] 05 6b }

  condition:
    any of them
}