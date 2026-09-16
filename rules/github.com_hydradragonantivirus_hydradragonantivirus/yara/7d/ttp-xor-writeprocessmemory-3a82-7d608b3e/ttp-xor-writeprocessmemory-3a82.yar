rule TTP_XOR_WriteProcessMemory_3a82 {
  strings:
    $key_3a82 = { 6d f0 [2] 5f d2 [2] 59 e7 [2] 77 e7 [2] 48 fb }

  condition:
    any of them
}