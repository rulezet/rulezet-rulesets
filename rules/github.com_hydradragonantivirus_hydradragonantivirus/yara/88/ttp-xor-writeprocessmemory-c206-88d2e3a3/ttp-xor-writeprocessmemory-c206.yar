rule TTP_XOR_WriteProcessMemory_c206 {
  strings:
    $key_c206 = { 95 74 [2] a7 56 [2] a1 63 [2] 8f 63 [2] b0 7f }

  condition:
    any of them
}