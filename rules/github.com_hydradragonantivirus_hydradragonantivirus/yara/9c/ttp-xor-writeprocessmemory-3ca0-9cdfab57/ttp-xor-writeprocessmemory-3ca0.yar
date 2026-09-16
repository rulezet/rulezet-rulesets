rule TTP_XOR_WriteProcessMemory_3ca0 {
  strings:
    $key_3ca0 = { 6b d2 [2] 59 f0 [2] 5f c5 [2] 71 c5 [2] 4e d9 }

  condition:
    any of them
}