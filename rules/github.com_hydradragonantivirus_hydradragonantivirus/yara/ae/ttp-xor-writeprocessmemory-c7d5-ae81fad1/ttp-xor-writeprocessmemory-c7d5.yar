rule TTP_XOR_WriteProcessMemory_c7d5 {
  strings:
    $key_c7d5 = { 90 a7 [2] a2 85 [2] a4 b0 [2] 8a b0 [2] b5 ac }

  condition:
    any of them
}