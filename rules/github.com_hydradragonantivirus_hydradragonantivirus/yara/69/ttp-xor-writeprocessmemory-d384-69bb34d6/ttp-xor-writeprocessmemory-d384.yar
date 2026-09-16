rule TTP_XOR_WriteProcessMemory_d384 {
  strings:
    $key_d384 = { 84 f6 [2] b6 d4 [2] b0 e1 [2] 9e e1 [2] a1 fd }

  condition:
    any of them
}