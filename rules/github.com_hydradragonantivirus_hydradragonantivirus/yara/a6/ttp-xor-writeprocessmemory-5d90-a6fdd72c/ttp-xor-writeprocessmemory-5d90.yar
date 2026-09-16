rule TTP_XOR_WriteProcessMemory_5d90 {
  strings:
    $key_5d90 = { 0a e2 [2] 38 c0 [2] 3e f5 [2] 10 f5 [2] 2f e9 }

  condition:
    any of them
}