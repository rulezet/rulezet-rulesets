rule TTP_XOR_WriteProcessMemory_d582 {
  strings:
    $key_d582 = { 82 f0 [2] b0 d2 [2] b6 e7 [2] 98 e7 [2] a7 fb }

  condition:
    any of them
}