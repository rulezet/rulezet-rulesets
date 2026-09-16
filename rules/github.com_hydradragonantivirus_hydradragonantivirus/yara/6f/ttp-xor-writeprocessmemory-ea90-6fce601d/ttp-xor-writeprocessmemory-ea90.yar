rule TTP_XOR_WriteProcessMemory_ea90 {
  strings:
    $key_ea90 = { bd e2 [2] 8f c0 [2] 89 f5 [2] a7 f5 [2] 98 e9 }

  condition:
    any of them
}