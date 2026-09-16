rule TTP_XOR_WriteProcessMemory_d684 {
  strings:
    $key_d684 = { 81 f6 [2] b3 d4 [2] b5 e1 [2] 9b e1 [2] a4 fd }

  condition:
    any of them
}