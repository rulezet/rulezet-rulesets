rule TTP_XOR_WriteProcessMemory_d584 {
  strings:
    $key_d584 = { 82 f6 [2] b0 d4 [2] b6 e1 [2] 98 e1 [2] a7 fd }

  condition:
    any of them
}