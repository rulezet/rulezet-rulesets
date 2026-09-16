rule TTP_XOR_WriteProcessMemory_c6d5 {
  strings:
    $key_c6d5 = { 91 a7 [2] a3 85 [2] a5 b0 [2] 8b b0 [2] b4 ac }

  condition:
    any of them
}