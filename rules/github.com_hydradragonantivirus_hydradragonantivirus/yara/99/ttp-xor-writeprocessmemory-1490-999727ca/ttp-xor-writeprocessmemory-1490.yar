rule TTP_XOR_WriteProcessMemory_1490 {
  strings:
    $key_1490 = { 43 e2 [2] 71 c0 [2] 77 f5 [2] 59 f5 [2] 66 e9 }

  condition:
    any of them
}