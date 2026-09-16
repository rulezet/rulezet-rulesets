rule TTP_XOR_WriteProcessMemory_5a90 {
  strings:
    $key_5a90 = { 0d e2 [2] 3f c0 [2] 39 f5 [2] 17 f5 [2] 28 e9 }

  condition:
    any of them
}