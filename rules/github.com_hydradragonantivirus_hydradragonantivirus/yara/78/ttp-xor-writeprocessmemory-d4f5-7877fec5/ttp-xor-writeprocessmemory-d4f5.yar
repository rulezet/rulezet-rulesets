rule TTP_XOR_WriteProcessMemory_d4f5 {
  strings:
    $key_d4f5 = { 83 87 [2] b1 a5 [2] b7 90 [2] 99 90 [2] a6 8c }

  condition:
    any of them
}