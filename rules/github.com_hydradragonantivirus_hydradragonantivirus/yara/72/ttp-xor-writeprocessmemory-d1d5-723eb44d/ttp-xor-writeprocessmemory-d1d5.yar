rule TTP_XOR_WriteProcessMemory_d1d5 {
  strings:
    $key_d1d5 = { 86 a7 [2] b4 85 [2] b2 b0 [2] 9c b0 [2] a3 ac }

  condition:
    any of them
}