rule TTP_XOR_WriteProcessMemory_d5f5 {
  strings:
    $key_d5f5 = { 82 87 [2] b0 a5 [2] b6 90 [2] 98 90 [2] a7 8c }

  condition:
    any of them
}