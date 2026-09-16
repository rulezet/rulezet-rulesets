rule TTP_XOR_WriteProcessMemory_f0a5 {
  strings:
    $key_f0a5 = { a7 d7 [2] 95 f5 [2] 93 c0 [2] bd c0 [2] 82 dc }

  condition:
    any of them
}