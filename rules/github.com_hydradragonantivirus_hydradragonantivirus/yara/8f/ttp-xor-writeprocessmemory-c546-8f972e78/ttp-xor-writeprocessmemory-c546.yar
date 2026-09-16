rule TTP_XOR_WriteProcessMemory_c546 {
  strings:
    $key_c546 = { 92 34 [2] a0 16 [2] a6 23 [2] 88 23 [2] b7 3f }

  condition:
    any of them
}