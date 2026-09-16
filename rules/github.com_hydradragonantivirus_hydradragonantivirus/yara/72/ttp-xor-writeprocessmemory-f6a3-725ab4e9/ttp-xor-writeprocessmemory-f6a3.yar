rule TTP_XOR_WriteProcessMemory_f6a3 {
  strings:
    $key_f6a3 = { a1 d1 [2] 93 f3 [2] 95 c6 [2] bb c6 [2] 84 da }

  condition:
    any of them
}