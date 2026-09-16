rule TTP_XOR_WriteProcessMemory_d5a6 {
  strings:
    $key_d5a6 = { 82 d4 [2] b0 f6 [2] b6 c3 [2] 98 c3 [2] a7 df }

  condition:
    any of them
}