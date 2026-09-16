rule TTP_XOR_WriteProcessMemory_d4a3 {
  strings:
    $key_d4a3 = { 83 d1 [2] b1 f3 [2] b7 c6 [2] 99 c6 [2] a6 da }

  condition:
    any of them
}