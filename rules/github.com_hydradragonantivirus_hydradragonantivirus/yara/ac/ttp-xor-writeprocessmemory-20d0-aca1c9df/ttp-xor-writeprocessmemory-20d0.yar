rule TTP_XOR_WriteProcessMemory_20d0 {
  strings:
    $key_20d0 = { 77 a2 [2] 45 80 [2] 43 b5 [2] 6d b5 [2] 52 a9 }

  condition:
    any of them
}