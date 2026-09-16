rule TTP_XOR_WriteProcessMemory_4a90 {
  strings:
    $key_4a90 = { 1d e2 [2] 2f c0 [2] 29 f5 [2] 07 f5 [2] 38 e9 }

  condition:
    any of them
}