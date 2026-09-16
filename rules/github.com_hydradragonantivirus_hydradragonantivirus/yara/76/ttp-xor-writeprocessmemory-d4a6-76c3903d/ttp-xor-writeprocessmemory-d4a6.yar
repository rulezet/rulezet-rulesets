rule TTP_XOR_WriteProcessMemory_d4a6 {
  strings:
    $key_d4a6 = { 83 d4 [2] b1 f6 [2] b7 c3 [2] 99 c3 [2] a6 df }

  condition:
    any of them
}