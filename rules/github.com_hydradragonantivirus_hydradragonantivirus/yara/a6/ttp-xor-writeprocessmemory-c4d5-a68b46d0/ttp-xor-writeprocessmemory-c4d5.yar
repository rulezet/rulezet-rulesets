rule TTP_XOR_WriteProcessMemory_c4d5 {
  strings:
    $key_c4d5 = { 93 a7 [2] a1 85 [2] a7 b0 [2] 89 b0 [2] b6 ac }

  condition:
    any of them
}