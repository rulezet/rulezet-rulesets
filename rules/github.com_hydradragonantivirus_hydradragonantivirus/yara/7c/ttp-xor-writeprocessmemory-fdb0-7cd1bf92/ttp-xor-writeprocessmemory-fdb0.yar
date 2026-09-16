rule TTP_XOR_WriteProcessMemory_fdb0 {
  strings:
    $key_fdb0 = { aa c2 [2] 98 e0 [2] 9e d5 [2] b0 d5 [2] 8f c9 }

  condition:
    any of them
}