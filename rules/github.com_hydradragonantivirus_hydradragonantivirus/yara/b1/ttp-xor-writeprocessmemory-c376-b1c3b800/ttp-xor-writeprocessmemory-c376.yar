rule TTP_XOR_WriteProcessMemory_c376 {
  strings:
    $key_c376 = { 94 04 [2] a6 26 [2] a0 13 [2] 8e 13 [2] b1 0f }

  condition:
    any of them
}