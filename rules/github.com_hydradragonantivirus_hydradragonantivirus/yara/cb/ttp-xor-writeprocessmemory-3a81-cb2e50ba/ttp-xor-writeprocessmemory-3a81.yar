rule TTP_XOR_WriteProcessMemory_3a81 {
  strings:
    $key_3a81 = { 6d f3 [2] 5f d1 [2] 59 e4 [2] 77 e4 [2] 48 f8 }

  condition:
    any of them
}