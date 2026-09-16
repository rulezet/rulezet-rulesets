rule TTP_XOR_WriteProcessMemory_2681 {
  strings:
    $key_2681 = { 71 f3 [2] 43 d1 [2] 45 e4 [2] 6b e4 [2] 54 f8 }

  condition:
    any of them
}