rule TTP_XOR_WriteProcessMemory_0d90 {
  strings:
    $key_0d90 = { 5a e2 [2] 68 c0 [2] 6e f5 [2] 40 f5 [2] 7f e9 }

  condition:
    any of them
}