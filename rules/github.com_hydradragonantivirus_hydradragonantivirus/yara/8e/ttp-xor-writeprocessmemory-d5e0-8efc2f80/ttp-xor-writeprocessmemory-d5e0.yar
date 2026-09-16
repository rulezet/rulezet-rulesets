rule TTP_XOR_WriteProcessMemory_d5e0 {
  strings:
    $key_d5e0 = { 82 92 [2] b0 b0 [2] b6 85 [2] 98 85 [2] a7 99 }

  condition:
    any of them
}