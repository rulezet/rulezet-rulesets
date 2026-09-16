rule TTP_XOR_WriteProcessMemory_3a84 {
  strings:
    $key_3a84 = { 6d f6 [2] 5f d4 [2] 59 e1 [2] 77 e1 [2] 48 fd }

  condition:
    any of them
}