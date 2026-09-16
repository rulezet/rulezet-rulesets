rule TTP_XOR_WriteProcessMemory_c556 {
  strings:
    $key_c556 = { 92 24 [2] a0 06 [2] a6 33 [2] 88 33 [2] b7 2f }

  condition:
    any of them
}