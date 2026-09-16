rule TTP_XOR_WriteProcessMemory_d0a6 {
  strings:
    $key_d0a6 = { 87 d4 [2] b5 f6 [2] b3 c3 [2] 9d c3 [2] a2 df }

  condition:
    any of them
}