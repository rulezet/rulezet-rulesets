rule TTP_XOR_WriteProcessMemory_d746 {
  strings:
    $key_d746 = { 80 34 [2] b2 16 [2] b4 23 [2] 9a 23 [2] a5 3f }

  condition:
    any of them
}