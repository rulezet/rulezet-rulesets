rule TTP_XOR_WriteProcessMemory_d484 {
  strings:
    $key_d484 = { 83 f6 [2] b1 d4 [2] b7 e1 [2] 99 e1 [2] a6 fd }

  condition:
    any of them
}