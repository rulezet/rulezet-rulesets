rule TTP_XOR_WriteProcessMemory_f0a6 {
  strings:
    $key_f0a6 = { a7 d4 [2] 95 f6 [2] 93 c3 [2] bd c3 [2] 82 df }

  condition:
    any of them
}