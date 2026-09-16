rule TTP_XOR_WriteProcessMemory_d246 {
  strings:
    $key_d246 = { 85 34 [2] b7 16 [2] b1 23 [2] 9f 23 [2] a0 3f }

  condition:
    any of them
}