rule TTP_XOR_WriteProcessMemory_d546 {
  strings:
    $key_d546 = { 82 34 [2] b0 16 [2] b6 23 [2] 98 23 [2] a7 3f }

  condition:
    any of them
}