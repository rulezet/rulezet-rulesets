rule TTP_XOR_WriteProcessMemory_2a90 {
  strings:
    $key_2a90 = { 7d e2 [2] 4f c0 [2] 49 f5 [2] 67 f5 [2] 58 e9 }

  condition:
    any of them
}