rule TTP_XOR_WriteProcessMemory_c0a6 {
  strings:
    $key_c0a6 = { 97 d4 [2] a5 f6 [2] a3 c3 [2] 8d c3 [2] b2 df }

  condition:
    any of them
}