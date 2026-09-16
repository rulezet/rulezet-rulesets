rule TTP_XOR_WriteProcessMemory_6681 {
  strings:
    $key_6681 = { 31 f3 [2] 03 d1 [2] 05 e4 [2] 2b e4 [2] 14 f8 }

  condition:
    any of them
}