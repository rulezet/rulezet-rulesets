rule TTP_XOR_WriteProcessMemory_d446 {
  strings:
    $key_d446 = { 83 34 [2] b1 16 [2] b7 23 [2] 99 23 [2] a6 3f }

  condition:
    any of them
}