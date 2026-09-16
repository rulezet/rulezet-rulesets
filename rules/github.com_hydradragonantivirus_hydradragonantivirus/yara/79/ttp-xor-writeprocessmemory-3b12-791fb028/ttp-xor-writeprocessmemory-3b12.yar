rule TTP_XOR_WriteProcessMemory_3b12 {
  strings:
    $key_3b12 = { 6c 60 [2] 5e 42 [2] 58 77 [2] 76 77 [2] 49 6b }

  condition:
    any of them
}