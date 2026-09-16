rule TTP_XOR_WriteProcessMemory_3a90 {
  strings:
    $key_3a90 = { 6d e2 [2] 5f c0 [2] 59 f5 [2] 77 f5 [2] 48 e9 }

  condition:
    any of them
}