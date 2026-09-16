rule TTP_XOR_WriteProcessMemory_d4d5 {
  strings:
    $key_d4d5 = { 83 a7 [2] b1 85 [2] b7 b0 [2] 99 b0 [2] a6 ac }

  condition:
    any of them
}