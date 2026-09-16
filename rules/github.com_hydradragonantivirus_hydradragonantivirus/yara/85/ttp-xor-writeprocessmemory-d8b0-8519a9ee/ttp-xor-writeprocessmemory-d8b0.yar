rule TTP_XOR_WriteProcessMemory_d8b0 {
  strings:
    $key_d8b0 = { 8f c2 [2] bd e0 [2] bb d5 [2] 95 d5 [2] aa c9 }

  condition:
    any of them
}