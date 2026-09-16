rule TTP_XOR_WriteProcessMemory_d184 {
  strings:
    $key_d184 = { 86 f6 [2] b4 d4 [2] b2 e1 [2] 9c e1 [2] a3 fd }

  condition:
    any of them
}