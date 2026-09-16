rule TTP_XOR_WriteProcessMemory_d5f7 {
  strings:
    $key_d5f7 = { 82 85 [2] b0 a7 [2] b6 92 [2] 98 92 [2] a7 8e }

  condition:
    any of them
}