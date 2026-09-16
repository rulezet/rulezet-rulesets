rule TTP_XOR_WriteProcessMemory_3a80 {
  strings:
    $key_3a80 = { 6d f2 [2] 5f d0 [2] 59 e5 [2] 77 e5 [2] 48 f9 }

  condition:
    any of them
}