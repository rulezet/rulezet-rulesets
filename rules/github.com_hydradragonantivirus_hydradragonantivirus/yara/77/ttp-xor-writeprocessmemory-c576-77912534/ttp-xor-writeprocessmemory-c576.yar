rule TTP_XOR_WriteProcessMemory_c576 {
  strings:
    $key_c576 = { 92 04 [2] a0 26 [2] a6 13 [2] 88 13 [2] b7 0f }

  condition:
    any of them
}