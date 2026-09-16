rule TTP_XOR_WriteProcessMemory_d5a3 {
  strings:
    $key_d5a3 = { 82 d1 [2] b0 f3 [2] b6 c6 [2] 98 c6 [2] a7 da }

  condition:
    any of them
}