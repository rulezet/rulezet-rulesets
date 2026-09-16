rule TTP_XOR_WriteProcessMemory_5681 {
  strings:
    $key_5681 = { 01 f3 [2] 33 d1 [2] 35 e4 [2] 1b e4 [2] 24 f8 }

  condition:
    any of them
}