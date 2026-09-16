rule TTP_XOR_WriteProcessMemory_c5f5 {
  strings:
    $key_c5f5 = { 92 87 [2] a0 a5 [2] a6 90 [2] 88 90 [2] b7 8c }

  condition:
    any of them
}