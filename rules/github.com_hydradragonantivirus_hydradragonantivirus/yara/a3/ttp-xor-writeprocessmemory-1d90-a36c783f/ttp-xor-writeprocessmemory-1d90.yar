rule TTP_XOR_WriteProcessMemory_1d90 {
  strings:
    $key_1d90 = { 4a e2 [2] 78 c0 [2] 7e f5 [2] 50 f5 [2] 6f e9 }

  condition:
    any of them
}