rule TTP_XOR_WriteProcessMemory_c5d5 {
  strings:
    $key_c5d5 = { 92 a7 [2] a0 85 [2] a6 b0 [2] 88 b0 [2] b7 ac }

  condition:
    any of them
}