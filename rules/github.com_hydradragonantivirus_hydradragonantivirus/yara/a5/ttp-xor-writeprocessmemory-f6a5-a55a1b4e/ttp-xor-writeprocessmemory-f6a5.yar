rule TTP_XOR_WriteProcessMemory_f6a5 {
  strings:
    $key_f6a5 = { a1 d7 [2] 93 f5 [2] 95 c0 [2] bb c0 [2] 84 dc }

  condition:
    any of them
}