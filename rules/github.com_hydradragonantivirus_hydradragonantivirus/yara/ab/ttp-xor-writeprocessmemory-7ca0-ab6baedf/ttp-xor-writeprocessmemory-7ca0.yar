rule TTP_XOR_WriteProcessMemory_7ca0 {
  strings:
    $key_7ca0 = { 2b d2 [2] 19 f0 [2] 1f c5 [2] 31 c5 [2] 0e d9 }

  condition:
    any of them
}