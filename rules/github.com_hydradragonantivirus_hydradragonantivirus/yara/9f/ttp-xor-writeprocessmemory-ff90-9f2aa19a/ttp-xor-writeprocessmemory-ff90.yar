rule TTP_XOR_WriteProcessMemory_ff90 {
  strings:
    $key_ff90 = { a8 e2 [2] 9a c0 [2] 9c f5 [2] b2 f5 [2] 8d e9 }

  condition:
    any of them
}