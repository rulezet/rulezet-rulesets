rule TTP_XOR_WriteProcessMemory_c584 {
  strings:
    $key_c584 = { 92 f6 [2] a0 d4 [2] a6 e1 [2] 88 e1 [2] b7 fd }

  condition:
    any of them
}