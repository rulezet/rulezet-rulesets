rule TTP_XOR_WriteProcessMemory_7a90 {
  strings:
    $key_7a90 = { 2d e2 [2] 1f c0 [2] 19 f5 [2] 37 f5 [2] 08 e9 }

  condition:
    any of them
}