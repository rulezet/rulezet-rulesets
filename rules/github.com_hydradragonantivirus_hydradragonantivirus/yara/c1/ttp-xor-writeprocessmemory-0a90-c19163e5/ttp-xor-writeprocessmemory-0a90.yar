rule TTP_XOR_WriteProcessMemory_0a90 {
  strings:
    $key_0a90 = { 5d e2 [2] 6f c0 [2] 69 f5 [2] 47 f5 [2] 78 e9 }

  condition:
    any of them
}