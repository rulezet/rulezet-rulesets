rule TTP_XOR_WriteProcessMemory_c356 {
  strings:
    $key_c356 = { 94 24 [2] a6 06 [2] a0 33 [2] 8e 33 [2] b1 2f }

  condition:
    any of them
}