rule TTP_XOR_WriteProcessMemory_f0a3 {
  strings:
    $key_f0a3 = { a7 d1 [2] 95 f3 [2] 93 c6 [2] bd c6 [2] 82 da }

  condition:
    any of them
}